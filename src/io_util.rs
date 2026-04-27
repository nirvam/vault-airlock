use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub struct HttpRequest {
    pub method: &'static str,
    pub path: &'static str,
    pub body: String,
}

impl HttpRequest {
    pub fn post(path: &'static str, body: &str) -> Self {
        Self {
            method: "POST",
            path,
            body: body.to_string(),
        }
    }

    pub async fn send(&self, stream: &mut UnixStream) -> anyhow::Result<()> {
        let req_str = format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.method, self.path, self.body.len(), self.body
        );
        stream.write_all(req_str.as_bytes()).await?;
        // stream.shutdown().await?;

        let mut response = String::new();
        stream.read_to_string(&mut response).await?;

        if response.contains(" 200 ") || response.contains(" 204 ") {
            Ok(())
        } else {
            let status = response.lines().next().unwrap_or("Unknown Error");
            anyhow::bail!("Server returned error: {}", status);
        }
    }
}
