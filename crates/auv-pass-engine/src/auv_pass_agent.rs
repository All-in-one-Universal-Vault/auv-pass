// SPDX-License-Identifier: MulanPSL-2.0 OR Apache-2.0
//! SSH 密钥代理:密钥生命周期 + agent 协议编解码 + agent 服务(监听/请求循环/确认回调)。
//!
//! - 私钥容器 = OpenSSH openssh-key-v1,交 RustCrypto `ssh-key` crate 处理(零自研解析);
//! - 生成:内置 Ed25519(熵源 = OS getrandom,与 ssh-keygen 同源;私钥出生到入库明文不落盘);
//! - 导入:验口令后统一解密为 none 容器入库(外层已是 AEAD,双层口令无增益);
//! - 签名:Ed25519(agent 载荷,64 字节,确定性);协议编解码纯函数(帧格式 = uint32 长度前缀 + payload)。

use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{LineEnding, PrivateKey};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auv_pass_vault::AuvPassEntryId;
use crate::error::{Error, Result};

/// 库内 SSH 密钥(与密码条目同级受 AEAD 保护)。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuvPassSshKey {
    pub id: AuvPassEntryId,
    /// 展示名(库内管理用)。
    pub name: String,
    /// 密钥注释。
    pub comment: String,
    /// 算法(当前为 `ssh-ed25519`;RSA 导入留后续版本)。
    pub algorithm: String,
    /// 公钥一行(authorized_keys 直接可用)。
    pub public_line: String,
    /// wire 公钥 blob(agent 消息 12/13 用)。
    pub public_blob: Vec<u8>,
    /// OpenSSH 私钥容器(库内为 none 口令形态)。
    pub private_pem: String,
    /// 对外暴露开关(agent 列表只含已暴露密钥;默认 false)。
    #[serde(default)]
    pub exposed: bool,
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_str(buf: &mut Vec<u8>, s: &[u8]) {
    put_u32(buf, s.len() as u32);
    buf.extend_from_slice(s);
}

/// Ed25519 wire 公钥 blob = string "ssh-ed25519" + string 32 字节公钥。
fn ed25519_blob(pubkey: &ssh_key::public::Ed25519PublicKey) -> Vec<u8> {
    let mut b = Vec::with_capacity(51);
    put_str(&mut b, b"ssh-ed25519");
    put_str(&mut b, pubkey.as_ref());
    b
}

/// 解析(未加密)私钥容器:返回 (公钥一行, wire blob)。
fn parse_public(pem: &str) -> Result<(String, Vec<u8>)> {
    let key =
        PrivateKey::from_openssh(pem).map_err(|e| Error::Format(format!("私钥解析失败:{e}")))?;
    let kp = key
        .key_data()
        .ed25519()
        .ok_or_else(|| Error::Format("仅支持 Ed25519".into()))?;
    Ok((key.public_key().to_string(), ed25519_blob(&kp.public)))
}

/// 签名核心:由容器 PEM 直接签名(服务层与 vault 共用)。
fn sign_with_pem(pem: &str, data: &[u8]) -> Result<Vec<u8>> {
    use ed25519_dalek::Signer as _;
    let pk =
        PrivateKey::from_openssh(pem).map_err(|e| Error::Format(format!("库内私钥异常:{e}")))?;
    let kp = pk
        .key_data()
        .ed25519()
        .ok_or_else(|| Error::Format("仅支持 Ed25519".into()))?;
    let seed = kp.private.to_bytes();
    let sig = ed25519_dalek::SigningKey::from_bytes(&seed).sign(data);
    Ok(sig.to_bytes().to_vec())
}

/// 密钥指纹(SHA256(wire blob) 的 hex 形态;展示用)。
pub fn auv_pass_ssh_fingerprint_hex(key: &AuvPassSshKey) -> String {
    use sha2::Digest as _;
    let d = sha2::Sha256::digest(&key.public_blob);
    let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
    format!("SHA256:{hex}")
}

fn store_key(
    keys: &mut Vec<AuvPassSshKey>,
    name: &str,
    comment: String,
    pem: String,
) -> Result<AuvPassEntryId> {
    let _ = name;
    let (public_line, public_blob) = parse_public(&pem)?;
    let entry = AuvPassSshKey {
        id: Uuid::new_v4(),
        name: name.to_string(),
        comment,
        algorithm: "ssh-ed25519".into(),
        public_line,
        public_blob,
        private_pem: pem,
        exposed: false,
    };
    keys.push(entry);
    Ok(keys.last().unwrap().id)
}

impl crate::auv_pass_vault::AuvPassVault {
    /// 内置生成 Ed25519 密钥对并入库(私钥明文不落盘;返回新 id)。
    pub fn ssh_generate_ed25519(&mut self, name: &str) -> Result<AuvPassEntryId> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut seed[..]).map_err(|e| Error::Entropy(e.to_string()))?;
        let kp = Ed25519Keypair::from_seed(&seed);
        let comment = if name.is_empty() {
            "auv-pass".to_string()
        } else {
            name.to_string()
        };
        let key = PrivateKey::new(KeypairData::from(kp), comment.clone())
            .map_err(|e| Error::Format(format!("私钥构造失败:{e}")))?;
        let pem = key
            .to_openssh(LineEnding::LF)
            .map_err(|e| Error::Format(format!("私钥编码失败:{e}")))?
            .to_string();
        store_key(&mut self.model.ssh_keys, name, comment, pem)
    }

    /// 导入 OpenSSH 私钥(带口令则先验口令;入库为 none 容器形态)。
    pub fn ssh_import(
        &mut self,
        pem: &str,
        passphrase: Option<&str>,
        name: &str,
    ) -> Result<AuvPassEntryId> {
        let key = PrivateKey::from_openssh(pem)
            .map_err(|e| Error::Format(format!("私钥解析失败:{e}")))?;
        let key = if key.is_encrypted() {
            let pw = passphrase.ok_or_else(|| Error::Format("该私钥带口令,须提供口令".into()))?;
            key.decrypt(pw)
                .map_err(|e| Error::Format(format!("口令验证失败:{e}")))?
        } else {
            key
        };
        let comment = if key.comment().is_empty() {
            name.to_string()
        } else {
            key.comment().to_string()
        };
        let plain = key
            .to_openssh(LineEnding::LF)
            .map_err(|e| Error::Format(format!("私钥重编码失败:{e}")))?
            .to_string();
        store_key(&mut self.model.ssh_keys, name, comment, plain)
    }

    /// 密钥列表。
    pub fn ssh_keys(&self) -> &[AuvPassSshKey] {
        &self.model.ssh_keys
    }

    /// 导出私钥(OpenSSH 容器字符串;**无口令形态**,文件需妥善保管)。
    pub fn ssh_export_private(&self, id: AuvPassEntryId) -> Result<String> {
        self.model
            .ssh_keys
            .iter()
            .find(|k| k.id == id)
            .map(|k| k.private_pem.clone())
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))
    }

    /// 用指定密钥对数据签名(agent 载荷;Ed25519 确定性签名,64 字节)。
    pub fn ssh_sign(&self, id: AuvPassEntryId, data: &[u8]) -> Result<Vec<u8>> {
        let key = self
            .model
            .ssh_keys
            .iter()
            .find(|k| k.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        sign_with_pem(&key.private_pem, data)
    }

    /// 切换对外暴露(agent 上岗/下岗)。
    pub fn ssh_set_exposed(&mut self, id: AuvPassEntryId, exposed: bool) -> Result<()> {
        let k = self
            .model
            .ssh_keys
            .iter_mut()
            .find(|k| k.id == id)
            .ok_or_else(|| Error::EntryNotFound(id.to_string()))?;
        k.exposed = exposed;
        Ok(())
    }

    /// 已暴露(上岗)密钥快照(agent 服务用)。
    pub fn ssh_exposed_keys(&self) -> Vec<AuvPassSshKey> {
        self.model
            .ssh_keys
            .iter()
            .filter(|k| k.exposed)
            .cloned()
            .collect()
    }

    /// 删除密钥。
    pub fn ssh_delete(&mut self, id: AuvPassEntryId) -> Result<()> {
        let before = self.model.ssh_keys.len();
        self.model.ssh_keys.retain(|k| k.id != id);
        if self.model.ssh_keys.len() == before {
            return Err(Error::EntryNotFound(id.to_string()));
        }
        Ok(())
    }
}

// ===================== agent 协议编解码(帧 = uint32 长度 + payload) =====================

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(4 + payload.len());
    put_u32(&mut f, payload.len() as u32);
    f.extend_from_slice(payload);
    f
}

/// 消息 12:钥匙列表应答(完整帧:长度前缀 + payload)。
pub fn auv_pass_agent_build_identities_answer(keys: &[AuvPassSshKey]) -> Vec<u8> {
    let mut p = vec![12u8];
    put_u32(&mut p, keys.len() as u32);
    for k in keys {
        put_str(&mut p, &k.public_blob);
        put_str(&mut p, k.comment.as_bytes());
    }
    frame(&p)
}

fn read_u32(buf: &[u8], off: &mut usize) -> Result<u32> {
    let b: [u8; 4] = buf
        .get(*off..*off + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| Error::Format("agent 消息不完整".into()))?;
    *off += 4;
    Ok(u32::from_be_bytes(b))
}

fn read_str<'a>(buf: &'a [u8], off: &mut usize) -> Result<&'a [u8]> {
    let n = read_u32(buf, off)? as usize;
    let s = buf
        .get(*off..*off + n)
        .ok_or_else(|| Error::Format("agent 消息不完整".into()))?;
    *off += n;
    Ok(s)
}

/// 解析消息 13(签名请求 payload):返回 (公钥 blob, 数据, flags)。
pub fn auv_pass_agent_parse_sign_request(payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>, u32)> {
    let mut off = 0usize;
    if payload.first() != Some(&13) {
        return Err(Error::Format("非签名请求消息".into()));
    }
    off += 1;
    let key = read_str(payload, &mut off)?.to_vec();
    let data = read_str(payload, &mut off)?.to_vec();
    let flags = read_u32(payload, &mut off)?;
    Ok((key, data, flags))
}

/// 完整帧:长度前缀 + 14 签名应答。
pub fn auv_pass_agent_build_sign_response(signature: &[u8]) -> Vec<u8> {
    let mut p = vec![14u8];
    put_str(&mut p, signature);
    frame(&p)
}

/// 完整帧:长度前缀 + 5 失败(原因码,OpenSSH 扩展)。
pub fn auv_pass_agent_build_failure(code: u32) -> Vec<u8> {
    let mut p = vec![5u8];
    put_u32(&mut p, code);
    frame(&p)
}

// ===================== agent 服务(监听 + 请求循环 + 确认回调) =====================

use std::io::{Read as _, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// 签名确认回调(返回 false = 拒绝;TUI 弹窗/测试自动允许均由此注入)。
pub type AuvPassAgentConfirm = Box<dyn FnMut(&AuvPassSshKey, &[u8]) -> bool + Send>;

/// 运行中的 agent 句柄。
pub struct AuvPassAgentHandle {
    stop: Arc<AtomicBool>,
    log: Arc<Mutex<Vec<String>>>,
    /// 监听名(停止时自连唤醒 accept 用)。
    pub socket: String,
}

impl AuvPassAgentHandle {
    /// 停止服务(置标志并自连唤醒 accept 循环)。
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        use interprocess::local_socket::traits::Stream as _;
        use interprocess::local_socket::ToFsName as _;
        let sock = self.socket.clone();
        if let Ok(name) = sock
            .as_str()
            .to_fs_name::<interprocess::local_socket::GenericFilePath>()
        {
            let _ = interprocess::local_socket::Stream::connect(name);
        }
    }
    /// 服务日志(签名/拒绝/异常,时间顺序)。
    pub fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
    /// 已完成的签名计数。
    pub fn sign_count(&self) -> usize {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("SIGN"))
            .count()
    }
}

/// 默认监听名(Windows 命名管道 / Unix 域套接字文件;独立命名,与系统 agent 并存)。
pub fn auv_pass_agent_default_socket() -> String {
    if cfg!(windows) {
        r"\\.\pipe\auv-pass-ssh-agent".to_string()
    } else {
        format!("{}/auv-pass-agent.sock", std::env::temp_dir().display())
    }
}

/// 启动 agent 服务(快照模式:上岗钥匙集合在启动时固定;变更须重启)。
pub fn auv_pass_agent_start(
    keys: Vec<AuvPassSshKey>,
    socket: &str,
    mut confirm: AuvPassAgentConfirm,
) -> Result<AuvPassAgentHandle> {
    use interprocess::local_socket::traits::Listener as _;
    use interprocess::local_socket::ListenerOptions;
    use interprocess::local_socket::ToFsName as _;
    let listener = ListenerOptions::new()
        .name(
            socket
                .to_fs_name::<interprocess::local_socket::GenericFilePath>()
                .map_err(|e| Error::Format(format!("socket 名不合法:{e}")))?,
        )
        .create_sync()
        .map_err(|e| Error::Io(std::io::Error::other(format!("监听绑定失败:{e}"))))?;
    let stop = Arc::new(AtomicBool::new(false));
    let log = Arc::new(Mutex::new(Vec::new()));
    let st = stop.clone();
    let lg = log.clone();
    std::thread::spawn(move || {
        loop {
            if st.load(Ordering::Relaxed) {
                break;
            }
            let Ok(mut conn) = listener.accept() else {
                continue;
            };
            if st.load(Ordering::Relaxed) {
                break; // 停止唤醒的自连
            }
            serve_conn(&mut conn, &keys, &mut confirm, &lg);
        }
    });
    Ok(AuvPassAgentHandle {
        stop,
        log,
        socket: socket.to_string(),
    })
}

/// 单连接请求循环(读帧 → 分发 → 应答;帧长封顶 1MB)。
fn serve_conn(
    conn: &mut interprocess::local_socket::Stream,
    keys: &[AuvPassSshKey],
    confirm: &mut AuvPassAgentConfirm,
    log: &Arc<Mutex<Vec<String>>>,
) {
    loop {
        let mut lenb = [0u8; 4];
        if conn.read_exact(&mut lenb).is_err() {
            return; // 对端关闭
        }
        let len = u32::from_be_bytes(lenb) as usize;
        if len == 0 || len > 1024 * 1024 {
            let _ = conn.write_all(&auv_pass_agent_build_failure(5));
            return;
        }
        let mut payload = vec![0u8; len];
        if conn.read_exact(&mut payload).is_err() {
            return;
        }
        let resp = match payload.first() {
            Some(11) => auv_pass_agent_build_identities_answer(keys),
            Some(13) => match auv_pass_agent_parse_sign_request(&payload) {
                Ok((blob, data, _flags)) => match keys.iter().find(|k| k.public_blob == blob) {
                    Some(k) => {
                        if !confirm(k, &data) {
                            log.lock().unwrap().push(format!("DENY {}", k.name));
                            auv_pass_agent_build_failure(5)
                        } else {
                            match sign_with_pem(&k.private_pem, &data) {
                                Ok(sig) => {
                                    log.lock().unwrap().push(format!("SIGN {}", k.name));
                                    auv_pass_agent_build_sign_response(&sig)
                                }
                                Err(e) => {
                                    log.lock().unwrap().push(format!("ERR {} {e}", k.name));
                                    auv_pass_agent_build_failure(5)
                                }
                            }
                        }
                    }
                    None => {
                        log.lock().unwrap().push("REJECT unknown-blob".into());
                        auv_pass_agent_build_failure(5)
                    }
                },
                Err(_) => auv_pass_agent_build_failure(5),
            },
            _ => auv_pass_agent_build_failure(5), // deny-by-default
        };
        if conn.write_all(&resp).is_err() {
            return;
        }
    }
}
