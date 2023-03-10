use std::io;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() {
    let wait = vec![tokio::spawn(run_server(9875))];

    for t in wait {
        t.await.expect("server failed").unwrap();
    }
}

async fn run_server(port: u16) -> io::Result<()> {
    let bindaddr = format!("0.0.0.0:{}", port);
    let sock = UdpSocket::bind(&bindaddr).await?;
    println!("listening on {}", bindaddr);

    let mut buf = [0; 1024];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        println!("port {}: {} bytes received from {}", port, len, addr);
        println!(
            "port {}: buffer contents: {}",
            port,
            String::from_utf8_lossy(&buf)
        );
    }
}
