use std::{
    net::{Ipv4Addr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

use super::NetworkSnapshot;
use super::http::record_error;

pub(super) fn spawn_dns(
    socket: UdpSocket,
    observations: Arc<Mutex<NetworkSnapshot>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("permission-mode-dns-fixture".to_owned())
        .spawn(move || {
            let mut buffer = [0_u8; 512];
            let mut answer_number = 0_usize;
            while !stop.load(Ordering::Acquire) {
                match socket.recv_from(&mut buffer) {
                    Ok((size, peer)) => {
                        let query = buffer[..size].to_vec();
                        let address = if answer_number == 0 {
                            Ipv4Addr::LOCALHOST
                        } else {
                            Ipv4Addr::new(127, 0, 0, 2)
                        };
                        answer_number += 1;
                        let answer = dns_answer(&query, address);
                        match answer {
                            Some(answer) => {
                                {
                                    let mut snapshot = observations
                                        .lock()
                                        .expect("network fixture observation lock");
                                    snapshot.dns_queries.push(query);
                                    snapshot.dns_answers.push(answer.clone());
                                }
                                if let Err(error) = socket.send_to(&answer, peer) {
                                    record_error(
                                        &observations,
                                        format!("send controlled DNS reply: {error}"),
                                    );
                                }
                            }
                            None => {
                                let mut snapshot = observations
                                    .lock()
                                    .expect("network fixture observation lock");
                                snapshot.dns_queries.push(query);
                                snapshot
                                    .errors
                                    .push("malformed controlled DNS query".to_owned());
                            }
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => record_error(
                        &observations,
                        format!("receive controlled DNS query: {error}"),
                    ),
                }
            }
        })
        .expect("start bounded DNS fixture observer")
}

fn dns_answer(query: &[u8], address: Ipv4Addr) -> Option<Vec<u8>> {
    if query.len() < 17 || query[4..6] != [0, 1] {
        return None;
    }
    let mut question_end = 12;
    loop {
        let label_size = usize::from(*query.get(question_end)?);
        question_end += 1;
        if label_size == 0 {
            break;
        }
        question_end = question_end.checked_add(label_size)?;
        if question_end >= query.len() {
            return None;
        }
    }
    question_end = question_end.checked_add(4)?;
    if question_end != query.len() {
        return None;
    }
    let mut answer = Vec::with_capacity(query.len() + 16);
    answer.extend_from_slice(&query[..2]);
    answer.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
    answer.extend_from_slice(&query[12..question_end]);
    answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
    answer.extend_from_slice(&address.octets());
    Some(answer)
}
