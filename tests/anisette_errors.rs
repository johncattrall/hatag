use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use omnisette::remote_anisette_v3::{AnisetteState, RemoteAnisetteProviderV3};
use omnisette::{AnisetteError, AnisetteProvider, LoginClientInfo};

async fn header_request(response_status: &str, body: &str) -> AnisetteError {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let response = format!("HTTP/1.1 {response_status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buffer[..read]);
            if let Some(position) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..position]);
                let length: usize = headers.lines().find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
                }).unwrap();
                if request.len() >= position + 4 + length { break; }
            }
        }
        stream.write_all(response.as_bytes()).unwrap();
    });
    let directory = std::env::temp_dir().join(format!("hatag-anisette-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let mut fixture = plist::Dictionary::new();
    fixture.insert("keychain_identifier".into(), plist::Value::Data(vec![1; 16]));
    fixture.insert("adi_pb".into(), plist::Value::Data(vec![2; 32]));
    let state: AnisetteState = plist::from_value(&plist::Value::Dictionary(fixture)).unwrap();
    let state_path = directory.join("state.plist");
    plist::to_file_xml(&state_path, &state).unwrap();
    let before = std::fs::read(&state_path).unwrap();
    let mut provider = RemoteAnisetteProviderV3::new(format!("http://{address}"), LoginClientInfo::default(), directory.clone());
    let error = provider.get_anisette_headers().await.unwrap_err();
    server.join().unwrap();
    assert_eq!(std::fs::read(&state_path).unwrap(), before);
    assert!(provider.state.as_ref().unwrap().is_provisioned());
    std::fs::remove_dir_all(directory).unwrap();
    error
}

#[tokio::test]
async fn server_failure_preserves_status_and_provisioned_state() {
    let error = header_request("503 Service Unavailable", "{}").await;
    let AnisetteError::ReqwestError(error) = error else { panic!("Expected HTTP status error") };
    assert_eq!(error.status().unwrap().as_u16(), 503);
}

#[tokio::test]
async fn malformed_success_response_returns_parse_error_without_resetting_state() {
    let error = header_request("200 OK", "not-json").await;
    assert!(matches!(error, AnisetteError::ReqwestError(error) if error.is_decode()));
}

#[tokio::test]
async fn service_rejection_is_an_error_not_a_panic_or_payload_leak() {
    let error = header_request("200 OK", r#"{"result":"GetHeadersError","message":"synthetic-private-response"}"#).await;
    assert!(matches!(error, AnisetteError::RemoteHeaderError));
    assert!(!format!("{error:?}").contains("synthetic-private-response"));
}
