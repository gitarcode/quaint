#[cfg(test)]
mod tests {
    use quaint::{
        connector::{PostgreSql, PostgresUrl, Queryable},
        error::ErrorKind,
    };
    use std::{env, error::Error, path::PathBuf};
    use url::Url;

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    fn url(kind: &str, options: &[(&str, &str)]) -> Result<PostgresUrl, Box<dyn Error + Send + Sync>> {
        let mut url = Url::parse(&env::var(format!("QUAINT_TEST_{kind}_URL"))?)?;
        url.query_pairs_mut().extend_pairs(options.iter().copied());
        Ok(PostgresUrl::new(url)?)
    }

    fn fixture(name: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        Ok(PathBuf::from(env::var("QUAINT_TEST_CERTS")?)
            .join(name)
            .to_string_lossy()
            .into_owned())
    }

    async fn tls_used(client: &PostgreSql) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let result = client
            .query_raw("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()", &[])
            .await?;
        Ok(result
            .first()
            .and_then(|row| row.get("ssl"))
            .and_then(|value| value.as_bool())
            .ok_or("missing TLS status")?)
    }

    #[tokio::test]
    async fn strict_ca_and_scram_channel_binding() -> TestResult {
        let ca = fixture("ca.crt")?;
        let client = PostgreSql::new(url(
            "TLS",
            &[
                ("sslmode", "require"),
                ("sslaccept", "strict"),
                ("sslcert", &ca),
                ("channel_binding", "require"),
            ],
        )?)
        .await?;
        assert!(tls_used(&client).await?);
        Ok(())
    }

    #[tokio::test]
    async fn strict_rejects_unknown_ca_wrong_host_and_expired_certificate() -> TestResult {
        let ca = fixture("ca.crt")?;
        let without_ca = url("TLS", &[("sslmode", "require"), ("sslaccept", "strict")])?;
        let mut wrong_host = Url::parse(&env::var("QUAINT_TEST_TLS_URL")?)?;
        wrong_host.set_host(Some("127.0.0.1"))?;
        wrong_host.query_pairs_mut().extend_pairs([
            ("sslmode", "require"),
            ("sslaccept", "strict"),
            ("sslcert", ca.as_str()),
        ]);
        let expired = url(
            "EXPIRED",
            &[("sslmode", "require"), ("sslaccept", "strict"), ("sslcert", &ca)],
        )?;
        for config in [without_ca, PostgresUrl::new(wrong_host)?, expired] {
            let error = PostgreSql::new(config)
                .await
                .expect_err("strict certificate verification must fail");
            assert!(matches!(error.kind(), ErrorKind::TlsError { .. }), "{error:?}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn configured_invalid_certificate_acceptance_is_preserved() -> TestResult {
        for kind in ["TLS", "EXPIRED"] {
            let client = PostgreSql::new(url(
                kind,
                &[("sslmode", "require"), ("sslaccept", "accept_invalid_certs")],
            )?)
            .await?;
            assert!(tls_used(&client).await?);
        }
        Ok(())
    }

    #[tokio::test]
    async fn negotiation_preserves_disable_prefer_and_require() -> TestResult {
        for mode in ["disable", "prefer"] {
            let client = PostgreSql::new(url("PLAIN", &[("sslmode", mode)])?).await?;
            assert!(!tls_used(&client).await?);
        }
        let client = PostgreSql::new(url("TLS", &[("sslmode", "disable")])?).await?;
        assert!(!tls_used(&client).await?);
        let error = PostgreSql::new(url("PLAIN", &[("sslmode", "require")])?)
            .await
            .expect_err("TLS required against plaintext server");
        assert!(matches!(error.kind(), ErrorKind::TlsError { .. }), "{error:?}");
        Ok(())
    }

    #[tokio::test]
    async fn modern_and_legacy_pkcs12_client_identities() -> TestResult {
        let ca = fixture("ca.crt")?;
        for name in ["client.p12", "client-legacy.p12"] {
            let identity = fixture(name)?;
            let mut endpoint = Url::parse(&env::var("QUAINT_TEST_TLS_URL")?)?;
            endpoint.set_username("certuser").map_err(|_| "invalid username")?;
            endpoint.set_password(None).map_err(|_| "invalid password")?;
            endpoint.query_pairs_mut().extend_pairs([
                ("sslmode", "require"),
                ("sslaccept", "strict"),
                ("sslcert", ca.as_str()),
                ("sslidentity", identity.as_str()),
                ("sslpassword", "fixture-password"),
            ]);
            let client = PostgreSql::new(PostgresUrl::new(endpoint)?).await?;
            assert!(tls_used(&client).await?);
        }
        Ok(())
    }

    #[tokio::test]
    async fn malformed_certificates_and_wrong_identity_password_are_tls_errors() -> TestResult {
        let malformed = fixture("not-a-cert.pem")?;
        let identity = fixture("client.p12")?;
        for config in [
            url("TLS", &[("sslcert", &malformed)])?,
            url("TLS", &[("sslidentity", &identity), ("sslpassword", "wrong-password")])?,
        ] {
            let error = PostgreSql::new(config).await.expect_err("invalid TLS input must fail");
            assert!(matches!(error.kind(), ErrorKind::TlsError { .. }), "{error:?}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn sqlstate_and_server_detail_survive_tls() -> TestResult {
        let client = PostgreSql::new(url("TLS", &[("sslmode", "require")])?).await?;
        let error = client
            .query_raw("SELECT * FROM quaint_missing_tls_fixture", &[])
            .await
            .expect_err("missing relation must fail");
        assert_eq!(error.original_code(), Some("42P01"));
        assert!(error
            .original_message()
            .is_some_and(|message| message.contains("quaint_missing_tls_fixture")));
        Ok(())
    }

    #[tokio::test]
    async fn stalled_handshake_obeys_connect_timeout() -> TestResult {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let peer = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await?;
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            Ok::<_, std::io::Error>(())
        });
        let config = PostgresUrl::new(Url::parse(&format!(
            "postgresql://postgres:fixture@localhost:{port}/postgres?sslmode=require&connect_timeout=1"
        ))?)?;
        let result = tokio::time::timeout(std::time::Duration::from_secs(3), PostgreSql::new(config)).await;
        peer.abort();
        let error = result?.expect_err("stalled TLS negotiation must time out");
        assert!(matches!(error.kind(), ErrorKind::ConnectTimeout), "{error:?}");
        Ok(())
    }

    #[tokio::test]
    #[ignore = "run in a separate process with SSL_CERT_FILE set by the fixture runner"]
    async fn system_roots_are_used() -> TestResult {
        let client = PostgreSql::new(url("TLS", &[("sslmode", "require"), ("sslaccept", "strict")])?).await?;
        assert!(tls_used(&client).await?);
        Ok(())
    }
}
