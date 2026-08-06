#!/usr/bin/env python3
"""
Patch rustdesk-server to support TCP peer registration.

This patch modifies handle_tcp() in rendezvous_server.rs to:
1. Handle RegisterPeer over TCP (update peer address, store sink for push)
2. Handle RegisterPk over TCP (full validation, return OK instead of NOT_SUPPORT)
3. Add send_to_tcp_push() for persistent TCP connection message delivery
4. Route PunchHole/Relay delivery through TCP when target is TCP-registered

Background: The OSS rustdesk-server only supports UDP registration.
When a client has disable-udp=Y (forced TCP), registration fails because
handle_tcp() returns NOT_SUPPORT for RegisterPk and silently drops RegisterPeer.
This patch adds TCP registration support so clients behind UDP-blocking
firewalls (like QiAnXin EDR) can register and be reached.
"""

import sys
import os

def patch_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original = content
    patches_applied = 0
    patches_failed = []

    # ================================================================
    # Patch 1: Add send_to_tcp_push function after send_to_tcp_sync
    # ================================================================
    send_to_tcp_push_fn = '''
    #[inline]
    async fn send_to_tcp_push(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        // Send message via TCP without removing the sink from tcp_punch.
        // This allows persistent TCP connections (registered peers) to
        // receive pushed messages (PunchHole, etc.) without closing.
        let mut tcp_punch = self.tcp_punch.lock().await;
        if let Some(sink) = tcp_punch.get_mut(&try_into_v4(addr)) {
            if let Ok(bytes) = msg.write_to_bytes() {
                match sink {
                    Sink::TcpStream(s) => {
                        allow_err!(s.send(Bytes::from(bytes)).await);
                    }
                    Sink::Ws(ws) => {
                        allow_err!(ws.send(tungstenite::Message::Binary(bytes)).await);
                    }
                }
            }
        }
    }
'''

    # Find the end of send_to_tcp_sync function to insert after it
    sync_anchor = '''    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let mut sink = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        Self::send_to_sink(&mut sink, msg).await;
        Ok(())
    }'''

    if sync_anchor in content:
        content = content.replace(sync_anchor, sync_anchor + send_to_tcp_push_fn)
        patches_applied += 1
        print("[OK] Patch 1: Added send_to_tcp_push function")
    else:
        patches_failed.append("Patch 1: Could not find send_to_tcp_sync anchor")
        print("[FAIL] Patch 1: Could not find send_to_tcp_sync anchor")

    # ================================================================
    # Patch 2: Add RegisterPeer handling in handle_tcp
    # Insert before the PunchHoleRequest case
    # ================================================================
    register_peer_code = '''                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // TCP registration support (patched)
                    if !rp.id.is_empty() {
                        log::info!("TCP register peer: {:?} {:?}", &rp.id, &addr);
                        // Update peer address (TCP version of update_addr)
                        let request_pk = if let Some(peer) = self.pm.get_or(&rp.id).await {
                            let mut p = peer.write().await;
                            let ip = addr.ip();
                            let ip_change = if p.socket_addr.port() != 0 {
                                ip != p.socket_addr.ip()
                            } else {
                                ip.to_string() != p.info.ip
                            } && !ip.is_loopback();
                            let req_pk = p.pk.is_empty() || ip_change;
                            if !req_pk {
                                p.socket_addr = addr;
                                p.last_reg_time = Instant::now();
                            }
                            if ip_change && p.reg_pk.0 <= 2 {
                                let old_addr = if p.socket_addr.port() == 0 {
                                    p.info.ip.clone()
                                } else {
                                    p.socket_addr.to_string()
                                };
                                log::info!("IP change of {} from {} to {}", rp.id, old_addr, addr);
                            }
                            req_pk
                        } else {
                            true
                        };
                        // Send RegisterPeerResponse
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_peer_response(RegisterPeerResponse {
                            request_pk,
                            ..Default::default()
                        });
                        if sink.is_some() {
                            // First registration on this connection: send via sink, then store
                            Self::send_to_sink(sink, msg_out).await;
                            if let Some(s) = sink.take() {
                                self.tcp_punch.lock().await.insert(try_into_v4(addr), s);
                            }
                        } else {
                            // Heartbeat on existing connection: send via stored sink
                            self.send_to_tcp_push(msg_out, addr).await;
                        }
                        // Handle serial update
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            self.send_to_tcp_push(msg_out, addr).await;
                        }
                    }
                    return true;
                }
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // there maybe several attempt, so sink can be none'''

    old_punch_hole_start = '''                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // there maybe several attempt, so sink can be none'''

    if old_punch_hole_start in content:
        content = content.replace(old_punch_hole_start, register_peer_code, 1)
        patches_applied += 1
        print("[OK] Patch 2: Added RegisterPeer handling in handle_tcp")
    else:
        # Try alternate pattern
        alt_pattern = '''                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {'''
        if alt_pattern in content:
            content = content.replace(alt_pattern, register_peer_code, 1)
            patches_applied += 1
            print("[OK] Patch 2: Added RegisterPeer handling in handle_tcp (alt match)")
        else:
            patches_failed.append("Patch 2: Could not find PunchHoleRequest anchor")
            print("[FAIL] Patch 2: Could not find PunchHoleRequest anchor")

    # ================================================================
    # Patch 3: Replace RegisterPk NOT_SUPPORT with full TCP handling
    # ================================================================
    old_register_pk = '''                Some(rendezvous_message::Union::RegisterPk(_)) => {
                    let res = register_pk_response::Result::NOT_SUPPORT;
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: res.into(),
                        ..Default::default()
                    });
                    Self::send_to_sink(sink, msg_out).await;
                }'''

    new_register_pk = '''                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    // TCP RegisterPk support (patched) - full validation like UDP path
                    if rk.uuid.is_empty() || rk.pk.is_empty() {
                        return true;
                    }
                    let id = rk.id;
                    let ip = addr.ip().to_string();
                    if id.len() < 6 {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_pk_response(RegisterPkResponse {
                            result: UUID_MISMATCH.into(),
                            ..Default::default()
                        });
                        if sink.is_some() {
                            Self::send_to_sink(sink, msg_out).await;
                        } else {
                            self.send_to_tcp_push(msg_out, addr).await;
                        }
                        return true;
                    }
                    if !self.check_ip_blocker(&ip, &id).await {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_pk_response(RegisterPkResponse {
                            result: TOO_FREQUENT.into(),
                            ..Default::default()
                        });
                        if sink.is_some() {
                            Self::send_to_sink(sink, msg_out).await;
                        } else {
                            self.send_to_tcp_push(msg_out, addr).await;
                        }
                        return true;
                    }
                    let peer = self.pm.get_or(&id).await;
                    let (changed, ip_changed) = {
                        let peer = peer.read().await;
                        if peer.uuid.is_empty() {
                            (true, false)
                        } else {
                            if peer.uuid == rk.uuid {
                                if peer.info.ip != ip && peer.pk != rk.pk {
                                    log::warn!(
                                        "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                                        id, ip, rk.pk, peer.info.ip, peer.pk,
                                    );
                                    drop(peer);
                                    let mut msg_out = RendezvousMessage::new();
                                    msg_out.set_register_pk_response(RegisterPkResponse {
                                        result: UUID_MISMATCH.into(),
                                        ..Default::default()
                                    });
                                    if sink.is_some() {
                                        Self::send_to_sink(sink, msg_out).await;
                                    } else {
                                        self.send_to_tcp_push(msg_out, addr).await;
                                    }
                                    return true;
                                }
                            } else {
                                log::warn!(
                                    "Peer {} uuid mismatch: {:?} vs {:?}",
                                    id, rk.uuid, peer.uuid
                                );
                                drop(peer);
                                let mut msg_out = RendezvousMessage::new();
                                msg_out.set_register_pk_response(RegisterPkResponse {
                                    result: UUID_MISMATCH.into(),
                                    ..Default::default()
                                });
                                if sink.is_some() {
                                    Self::send_to_sink(sink, msg_out).await;
                                } else {
                                    self.send_to_tcp_push(msg_out, addr).await;
                                }
                                return true;
                            }
                            let ip_changed = peer.info.ip != ip;
                            (
                                peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                                ip_changed,
                            )
                        }
                    };
                    let mut req_pk = peer.read().await.reg_pk;
                    if req_pk.1.elapsed().as_secs() > 6 {
                        req_pk.0 = 0;
                    } else if req_pk.0 > 2 {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_pk_response(RegisterPkResponse {
                            result: TOO_FREQUENT.into(),
                            ..Default::default()
                        });
                        if sink.is_some() {
                            Self::send_to_sink(sink, msg_out).await;
                        } else {
                            self.send_to_tcp_push(msg_out, addr).await;
                        }
                        return true;
                    }
                    req_pk.0 += 1;
                    req_pk.1 = Instant::now();
                    peer.write().await.reg_pk = req_pk;
                    if ip_changed {
                        let mut lock = IP_CHANGES.lock().await;
                        if let Some((tm, ips)) = lock.get_mut(&id) {
                            if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                                *tm = Instant::now();
                                ips.clear();
                                ips.insert(ip.clone(), 1);
                            } else if let Some(v) = ips.get_mut(&ip) {
                                *v += 1;
                            } else {
                                ips.insert(ip.clone(), 1);
                            }
                        } else {
                            lock.insert(
                                id.clone(),
                                (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                            );
                        }
                    }
                    if changed {
                        self.pm.update_pk(id, peer, addr, rk.uuid, rk.pk, ip).await;
                    }
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: register_pk_response::Result::OK.into(),
                        ..Default::default()
                    });
                    if sink.is_some() {
                        Self::send_to_sink(sink, msg_out).await;
                    } else {
                        self.send_to_tcp_push(msg_out, addr).await;
                    }
                    return true;
                }'''

    if old_register_pk in content:
        content = content.replace(old_register_pk, new_register_pk, 1)
        patches_applied += 1
        print("[OK] Patch 3: Replaced RegisterPk NOT_SUPPORT with full TCP handling")
    else:
        patches_failed.append("Patch 3: Could not find RegisterPk NOT_SUPPORT block")
        print("[FAIL] Patch 3: Could not find RegisterPk NOT_SUPPORT block")

    # ================================================================
    # Patch 4: Change send_to_tcp to send_to_tcp_push in handle_hole_sent
    # ================================================================
    old_hole_sent = '''        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr'''

    new_hole_sent = '''        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp_push(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr'''

    if old_hole_sent in content:
        content = content.replace(old_hole_sent, new_hole_sent, 1)
        patches_applied += 1
        print("[OK] Patch 4: Changed handle_hole_sent to use send_to_tcp_push")
    else:
        patches_failed.append("Patch 4: Could not find handle_hole_sent anchor")
        print("[FAIL] Patch 4: Could not find handle_hole_sent anchor")

    # ================================================================
    # Patch 5: Change send_to_tcp to send_to_tcp_push in handle_local_addr
    # ================================================================
    old_local_addr = '''        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request'''

    new_local_addr = '''        if let Some(socket) = socket {
            socket.send(&msg_out, addr_a).await?;
        } else {
            self.send_to_tcp_push(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request'''

    if old_local_addr in content:
        content = content.replace(old_local_addr, new_local_addr, 1)
        patches_applied += 1
        print("[OK] Patch 5: Changed handle_local_addr to use send_to_tcp_push")
    else:
        patches_failed.append("Patch 5: Could not find handle_local_addr anchor")
        print("[FAIL] Patch 5: Could not find handle_local_addr anchor")

    # ================================================================
    # Patch 6: Change send_to_tcp_sync to send_to_tcp_push in RelayResponse
    # ================================================================
    old_relay_response = '''                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);'''
    new_relay_response = '''                    allow_err!(self.send_to_tcp_push(msg_out, addr_b).await);'''

    if old_relay_response in content:
        content = content.replace(old_relay_response, new_relay_response, 1)
        patches_applied += 1
        print("[OK] Patch 6: Changed RelayResponse to use send_to_tcp_push")
    else:
        patches_failed.append("Patch 6: Could not find RelayResponse anchor")
        print("[FAIL] Patch 6: Could not find RelayResponse anchor")

    # ================================================================
    # Patch 7: Modify RequestRelay to try TCP delivery for target peer
    # ================================================================
    old_request_relay = '''                    if let Some(peer) = self.pm.get_in_memory(&rf.id).await {
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        msg_out.set_request_relay(rf);
                        let peer_addr = peer.read().await.socket_addr;
                        self.tx.send(Data::Msg(msg_out.into(), peer_addr)).ok();
                    }'''

    new_request_relay = '''                    if let Some(peer) = self.pm.get_in_memory(&rf.id).await {
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        msg_out.set_request_relay(rf);
                        let peer_addr = peer.read().await.socket_addr;
                        // Try TCP delivery first (for TCP-registered peers)
                        let has_tcp = self.tcp_punch.lock().await.contains_key(&try_into_v4(peer_addr));
                        if has_tcp {
                            self.send_to_tcp_push(msg_out, peer_addr).await;
                        } else {
                            self.tx.send(Data::Msg(msg_out.into(), peer_addr)).ok();
                        }
                    }'''

    if old_request_relay in content:
        content = content.replace(old_request_relay, new_request_relay, 1)
        patches_applied += 1
        print("[OK] Patch 7: Modified RequestRelay to try TCP delivery")
    else:
        patches_failed.append("Patch 7: Could not find RequestRelay anchor")
        print("[FAIL] Patch 7: Could not find RequestRelay anchor")

    # ================================================================
    # Patch 8: Modify handle_tcp_punch_hole_request for TCP delivery
    # ================================================================
    old_punch_hole_req = '''    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        if let Some(addr) = to_addr {
            self.tx.send(Data::Msg(msg.into(), addr))?;
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }'''

    new_punch_hole_req = '''    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        if let Some(peer_addr) = to_addr {
            // Try TCP delivery first (for TCP-registered peers)
            let has_tcp = self.tcp_punch.lock().await.contains_key(&try_into_v4(peer_addr));
            if has_tcp {
                self.send_to_tcp_push(msg, peer_addr).await;
            } else {
                self.tx.send(Data::Msg(msg.into(), peer_addr))?;
            }
        } else {
            self.send_to_tcp_push(msg, addr).await;
        }
        Ok(())
    }'''

    if old_punch_hole_req in content:
        content = content.replace(old_punch_hole_req, new_punch_hole_req, 1)
        patches_applied += 1
        print("[OK] Patch 8: Modified handle_tcp_punch_hole_request for TCP delivery")
    else:
        patches_failed.append("Patch 8: Could not find handle_tcp_punch_hole_request anchor")
        print("[FAIL] Patch 8: Could not find handle_tcp_punch_hole_request anchor")

    # ================================================================
    # Write patched file
    # ================================================================
    if content == original:
        print("\n[ERROR] No patches were applied! File unchanged.")
        sys.exit(1)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"\n=== Patch Summary ===")
    print(f"Applied: {patches_applied}/8 patches")
    if patches_failed:
        print(f"Failed: {len(patches_failed)}")
        for p in patches_failed:
            print(f"  - {p}")
        print("\n[WARNING] Some patches failed. The build may not work correctly.")
        sys.exit(1)
    else:
        print("All patches applied successfully!")
        print(f"Modified file: {filepath}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        # Default path in the repo
        filepath = 'src/rendezvous_server.rs'
    else:
        filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    print(f"Patching: {filepath}")
    patch_file(filepath)
