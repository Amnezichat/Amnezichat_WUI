mod gui;
mod key_operations;
mod network_operations;
mod key_exchange;
mod authentication;
mod encryption;

use gui::{create_rocket, MessagingApp};
use key_operations::{key_operations_dilithium, key_operations_eddsa};
use network_operations::{
    create_client_with_proxy,
    fetch_kyber_pubkey,
    fetch_dilithium_pubkeys,
    fetch_eddsa_pubkeys,
    fetch_ciphertext,
    send_kyber_pubkey,
    send_dilithium_pubkey,
    send_eddsa_pubkey,
    send_ciphertext,
    send_encrypted_message,
    receive_and_fetch_messages,
};
use key_exchange::{kyber_key_exchange, perform_ecdh_key_exchange};
use authentication::{
    sign_data_with_dilithium,
    sign_data_with_eddsa,
    verify_signature_with_dilithium,
    verify_signature_with_eddsa,
};
use encryption::{
    derive_salt_from_password,
    derive_key,
    combine_shared_secrets,
    encrypt_data,
    decrypt_data,
};

use oqs::*;
use oqs::sig::{Sig, PublicKey, SecretKey, Algorithm as SigAlgorithm};
use rand::Rng;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use hex;
use std::io::{self, Write};
use std::result::Result;
use std::{
    collections::HashSet,
    error::Error,
};
use std::fs;
use serde::{Deserialize, Serialize};
use chacha20poly1305::aead::OsRng;
use rand::RngCore;
use sha3::{Sha3_512, Digest};
use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use eframe::egui;
use rfd::MessageDialog;
use rfd::MessageButtons;
use rfd::MessageLevel;
use rfd::MessageDialogResult;
use std::process::Stdio;
use rocket::Config;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use which::which;

fn get_raw_bytes_public_key(pk: &PublicKey) -> &[u8] {
    pk.as_ref() 
}

fn get_raw_bytes_secret_key(sk: &SecretKey) -> &[u8] {
    sk.as_ref() 
}

#[derive(Serialize, Deserialize, Debug)] 
struct MessageData {
    message: String,
    room_id: String,
}

fn fingerprint_dilithium_public_key(public_key: &PublicKey) -> String {

    let raw_bytes = public_key.as_ref(); 
    let hashed = Sha3_512::digest(raw_bytes);
    hex::encode(hashed)
}

fn fingerprint_eddsa_public_key(public_key: &Ed25519PublicKey) -> String {

    let hashed = Sha3_512::digest(public_key);
    hex::encode(hashed)
}

fn request_user_confirmation(
    fingerprint: &str,
    own_fingerprint: &str,
    password: &str,
) -> Result<bool, io::Error> {
    if fingerprint == own_fingerprint {
        return Ok(true);
    }

    let path = "contact_fingerprints.enc";
    let trusted_fingerprints = load_trusted_fingerprints(path, password)?;

    if trusted_fingerprints.contains(fingerprint) {
        println!("Auto-trusting stored fingerprint: {}", fingerprint);
        return Ok(true);
    }

    let message = format!(
        "🔒 Fingerprint Verification\n\n\
         Your fingerprint:\n{}\n\n\
         Received fingerprint:\n{}\n\n\
         Do you want to trust the received fingerprint?",
        own_fingerprint, fingerprint
    );

    let confirm = MessageDialog::new()
        .set_title("Trust New Fingerprint")
        .set_level(MessageLevel::Info)
        .set_description(&message)
        .set_buttons(MessageButtons::YesNo)
        .show();

    if confirm == MessageDialogResult::Yes {
        let remember = MessageDialog::new()
            .set_title("Remember Fingerprint?")
            .set_level(MessageLevel::Info)
            .set_description(
                "💾 Would you like to remember this fingerprint for future sessions?\n\
                 This prevents asking again for the same contact."
            )
            .set_buttons(MessageButtons::YesNo)
            .show();

        if remember == MessageDialogResult::Yes {
            save_fingerprint(path, fingerprint, password)?;
        }

        Ok(true)
    } else {
        Ok(false)
    }
}

fn load_trusted_fingerprints<P: AsRef<Path>>(
    path: P,
    password: &str
) -> Result<HashSet<String>, io::Error> {
    let mut set = HashSet::new();

    if let Ok(file) = File::open(&path) {
        for line in BufReader::new(file).lines() {
            if let Ok(encrypted_line) = line {
                match decrypt_data(&encrypted_line, password) {
                    Ok(fingerprint) => {
                        set.insert(fingerprint);
                    }
                    Err(err) => {
                        eprintln!("Warning: Could not decrypt a line in fingerprint file: {}", err);
                    }
                }
            }
        }
    }

    Ok(set)
}

fn save_fingerprint<P: AsRef<Path>>(
    path: P,
    fingerprint: &str,
    password: &str
) -> Result<(), io::Error> {
    match encrypt_data(fingerprint, password) {
        Ok(encrypted) => {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            writeln!(file, "{}", encrypted)?;
            Ok(())
        }
        Err(e) => {
            eprintln!("Encryption error: {}", e);
            Err(io::Error::new(io::ErrorKind::Other, "Failed to encrypt fingerprint"))
        }
    }
}

fn generate_random_room_id() -> String {
    const ID_LENGTH: usize = 16;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let mut rng = OsRng;
    let mut room_id = String::with_capacity(ID_LENGTH);

    for _ in 0..ID_LENGTH {
        let idx = (rng.next_u32() as usize) % CHARSET.len();
        room_id.push(CHARSET[idx] as char);
    }

    room_id
}

fn pad_message(message: &str, max_length: usize) -> String {
    let current_length = message.len();

    if current_length < max_length {
        let padding_len = max_length - current_length;

        let mut rng = OsRng;  
        let padding: String = (0..padding_len)
            .map(|_| rng.gen_range(33..127) as u8 as char) 
            .collect();

        return format!("{}<padding>{}</padding>", message, padding);
    }

    message.to_string()  
}

#[derive(Clone)]
struct AppState {
    choice: String,
    server_url: String,
    username: String,
    private_password: String,
    is_group_chat: bool,
    show_url_label: bool,
    room_id_input: String,
    room_password: String,
    error_message: Option<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            choice: "".into(),
            server_url: "".into(),
            username: "".into(),
            private_password: "".into(),
            is_group_chat: false,
            show_url_label: false,
            room_id_input: "".into(),
            room_password: "".into(),
            error_message: None,
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut options = eframe::NativeOptions::default();
    options.viewport.resizable = Some(false);
    options.viewport.inner_size = Some(egui::vec2(600.0, 1000.0));
    eframe::run_native(
        "Messaging Setup",
        options,
        Box::new(|_cc| Box::new(SetupApp::new())),
    )?;
    Ok(())
}

struct SetupApp {
    state: AppState,
    config_server_url: String,
}

impl SetupApp {
    fn new() -> Self {
        let config_server_url = load_server_url_from_rocket_toml()
            .unwrap_or_else(|_| "http://127.0.0.1:8000".to_string());

        Self {
            state: AppState::default(),
            config_server_url,
        }
    }
}

fn load_server_url_from_rocket_toml() -> Result<String, Box<dyn std::error::Error>> {
    let config = Config::figment().extract::<Config>()?;
    let address = config.address.to_string();
    let port = config.port;
    Ok(format!("http://{}:{}", address, port))
}

impl eframe::App for SetupApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.heading(egui::RichText::new("Amnezichat").size(40.0));
                ui.add_space(30.0);

                egui::Frame::group(ui.style())
                    .inner_margin(egui::style::Margin::symmetric(20.0, 20.0))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("Choose an action:").size(24.0));
                            ui.add_space(10.0);
                            ui.horizontal_wrapped(|ui| {
                                ui.add_space(20.0);
                                if ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new("➕ Create Room").size(24.0),
                                        )
                                        .min_size(egui::vec2(200.0, 60.0))
                                        .fill(egui::Color32::from_rgb(50, 50, 50)),
                                    )
                                    .clicked()
                                {
                                    self.state.choice = "create".into();
                                    self.state.room_id_input = generate_random_room_id();
                                }
                                ui.add_space(100.0);
                                if ui
                                    .add(
                                        egui::Button::new(
                                            egui::RichText::new("🔗 Join Room").size(24.0),
                                        )
                                        .min_size(egui::vec2(200.0, 60.0))
                                        .fill(egui::Color32::from_rgb(50, 50, 50)),
                                    )
                                    .clicked()
                                {
                                    self.state.choice = "join".into();
                                }
                            });

                            ui.add_space(20.0);

                            match self.state.choice.as_str() {
                                "join" => {
                                    ui.separator();
                                    ui.label(
                                        egui::RichText::new("🔑 Enter Room ID:").size(22.0),
                                    );
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.state.room_id_input)
                                            .font(egui::TextStyle::Heading)
                                            .desired_width(300.0),
                                    );
                                }
                                "create" => {
                                    if !self.state.room_id_input.is_empty() {
                                        ui.separator();
                                        ui.label(
                                            egui::RichText::new("🆔 Generated Room ID:").size(22.0),
                                        );
                                        ui.code(
                                            egui::RichText::new(&self.state.room_id_input)
                                                .size(20.0),
                                        );
                                    }
                                }
                                _ => {}
                            }
                        });
                    });

                ui.add_space(30.0);

                egui::Frame::group(ui.style())
                    .inner_margin(egui::style::Margin::symmetric(20.0, 20.0))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.heading(egui::RichText::new("🔧 Connection Details").size(36.0));
                            ui.add_space(20.0);

                            egui::Grid::new("connection_details")
                                .num_columns(2)
                                .spacing([50.0, 16.0])
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("Server URL:").size(22.0));
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.state.server_url)
                                            .font(egui::TextStyle::Heading)
                                            .desired_width(300.0),
                                    );
                                    ui.end_row();

                                    ui.label(egui::RichText::new("Username:").size(22.0));
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.state.username)
                                            .font(egui::TextStyle::Heading)
                                            .desired_width(300.0),
                                    );
                                    ui.end_row();

                                    ui.label(egui::RichText::new("Private Password:").size(22.0));
                                    ui.add(
                                        egui::TextEdit::singleline(
                                            &mut self.state.private_password,
                                        )
                                        .password(true)
                                        .font(egui::TextStyle::Heading)
                                        .desired_width(300.0),
                                    );
                                    ui.end_row();
                                });

                            ui.add_space(20.0);
                            ui.checkbox(
                                &mut self.state.is_group_chat,
                                egui::RichText::new("👥 Is Group Chat?").size(22.0),
                            );

                            if self.state.is_group_chat {
                                ui.add_space(20.0);
                                ui.label(
                                    egui::RichText::new("🔒 Room Password (min 8 chars):")
                                        .size(22.0),
                                );
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.state.room_password)
                                        .font(egui::TextStyle::Heading)
                                        .desired_width(300.0),
                                );
                            }
                        });
                    });

                ui.add_space(30.0);

                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("🚀 Start Messaging").size(28.0),
                        )
                        .fill(egui::Color32::from_rgb(0, 100, 0))
                        .min_size(egui::vec2(250.0, 60.0)),
                    )
                    .clicked()
                {
                    if let Err(err) = validate_and_start(self.state.clone()) {
                        self.state.error_message = Some(err.to_string());
                    } else {
                        self.state.show_url_label = true;
                    }
                }

                ui.add_space(20.0);

                if ui
                    .add(
                        egui::Button::new(egui::RichText::new("🌐 Host Server").size(24.0))
                            .fill(egui::Color32::from_rgb(30, 30, 150))
                            .min_size(egui::vec2(250.0, 50.0)),
                    )
                    .clicked()
                {
                    self.state.error_message = None;
                    std::thread::spawn(|| {
                        if let Err(e) = host_server() {
                            eprintln!("Host server error: {}", e);
                        }
                    });
                }

                if let Some(err) = &self.state.error_message {
                    ui.add_space(20.0);
                    ui.colored_label(
                        egui::Color32::RED,
                        egui::RichText::new(format!("❗ {}", err)).size(22.0),
                    );
                }

                if self.state.show_url_label {
                    ui.add_space(20.0);
                    ui.label(
                        egui::RichText::new(format!(
                            "Open {} in your web browser",
                            self.config_server_url
                        ))
                        .size(22.0),
                    );
                }
            });
        });
    }
}

fn host_server() -> Result<(), Box<dyn std::error::Error>> {
    let pkg_install = if which("apt").is_ok() {
        "sudo apt update && sudo apt install -y git curl build-essential tor"
    } else if which("dnf").is_ok() {
        "sudo dnf install -y git curl gcc cmake make kernel-devel tor"
    } else if which("pacman").is_ok() {
        "sudo pacman -Sy --noconfirm git curl base-devel tor"
    } else {
        return Err("No supported package manager found".into());
    };

    Command::new("xterm")
        .arg("-e")
        .arg(format!("bash -c '{}'", pkg_install))
        .spawn()?
        .wait()?;

    let setup_script = r#"
        #!/bin/bash
        set -e

        if ! command -v cargo &> /dev/null; then
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
            source $HOME/.cargo/env
        fi

        if [ ! -d "Amnezichat_Server" ]; then
            git clone https://git.disroot.org/UmutCamliyurt/Amnezichat_Server.git
        fi

        cd Amnezichat_Server

        find . -mindepth 1 -maxdepth 1 ! -name 'server' -exec rm -rf {} +

        cd server
        cargo build --release
        cargo run --release
    "#;

    fs::write("start_server.sh", setup_script)?;
    #[cfg(unix)]
    fs::set_permissions("start_server.sh", fs::Permissions::from_mode(0o755))?;

    Command::new("xterm")
        .arg("-e")
        .arg("bash -c './start_server.sh'")
        .spawn()?
        .wait()?;

    configure_tor_for_onion_service()?;

    Ok(())
}

fn configure_tor_for_onion_service() -> Result<(), Box<dyn std::error::Error>> {
    let hidden_dir = "./hidden_service";
    fs::create_dir_all(hidden_dir)?;
    #[cfg(unix)]
    fs::set_permissions(hidden_dir, fs::Permissions::from_mode(0o700))?;

    let torrc_path = format!("{}/torrc", hidden_dir);
    let torrc_content = format!(
        "HiddenServiceDir {}\nHiddenServicePort 80 127.0.0.1:8080\n",
        hidden_dir
    );
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&torrc_path)?;
    file.write_all(torrc_content.as_bytes())?;

    let _ = Command::new("pkill").arg("tor").output();

    let tor_cmd = format!("tor -f {}", torrc_path);
    Command::new("nohup")
        .arg("bash")
        .arg("-c")
        .arg(&tor_cmd)
        .stdout(Stdio::null()) 
        .stderr(Stdio::null()) 
        .spawn()?;

    let hostname_path = format!("{}/hostname", hidden_dir);
    let start_time = std::time::Instant::now();
    while !Path::new(&hostname_path).exists() {
        if start_time.elapsed().as_secs() > 30 {
            return Err("Timeout waiting for Tor to create the .onion address.".into());
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    let onion = fs::read_to_string(&hostname_path)?.trim().to_string();
    println!("Your Amnezichat server is live at: http://{}", onion);

    MessageDialog::new()
        .set_title("Tor Hidden Service")
        .set_description(&format!("Your Amnezichat server is live at: http://{}", onion))
        .show();

    Ok(())
}

fn validate_and_start(state: AppState) -> Result<(), Box<dyn Error>> {
    if state.server_url.is_empty() || state.username.is_empty() || state.private_password.is_empty() {
        return Err("Please fill in all fields.".into());
    }
    if state.is_group_chat && state.room_password.len() <= 8 {
        return Err("Room password must be longer than 8 characters.".into());
    }

    std::thread::spawn(move || {
        if let Err(e) = run_app_logic(state) {
            eprintln!("App error: {}", e);
        }
    });

    Ok(())
}

fn run_app_logic(state: AppState) -> Result<(), Box<dyn Error>> {

    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium5)?;

    let room_id = state.room_id_input.clone();
    let url = state.server_url.clone();
    let username = state.username.clone();
    let private_password = state.private_password.clone();

    let room_password = if state.is_group_chat {
        let salt = derive_salt_from_password(&state.room_password);
        let key = derive_key(&state.room_password, &salt);
        hex::encode(key)
    } else {
        String::new()
    };

    if state.is_group_chat {
        println!("Skipping key exchange. Using room password as shared secret.");
        let hybrid_shared_secret = room_password.clone();
        println!("Shared secret established.");
        println!("You can now start messaging!");

        let shared_hybrid_secret = Arc::new(hybrid_shared_secret.clone());
        let shared_room_id = Arc::new(Mutex::new(room_id.clone()));
        let shared_url = Arc::new(Mutex::new(url.clone()));

        let random_data_thread = {
            let shared_room_id = Arc::clone(&shared_room_id);
            let shared_url = Arc::clone(&shared_url);
            let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);

            thread::spawn(move || loop {
                let mut random_data = vec![0u8; OsRng.next_u32() as usize % 2048 + 1];
                OsRng.fill_bytes(&mut random_data);

                let dummy_message = format!("[DUMMY_DATA]: {:?}", random_data);
                let encrypted_dummy_message = match encrypt_data(&dummy_message, &shared_hybrid_secret) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("Error encrypting dummy message: {}", e);
                        continue;
                    }
                };

                let room_id_locked = shared_room_id.lock().unwrap();
                let url_locked = shared_url.lock().unwrap();
                let padded_message = pad_message(&encrypted_dummy_message, 2048);

                if let Err(e) = send_encrypted_message(&padded_message, &room_id_locked, &url_locked) {
                    eprintln!("Error sending dummy message: {}", e);
                }

                thread::sleep(Duration::from_secs(OsRng.next_u32() as u64 % 120 + 1));
            })
        };

        let fetch_thread = thread::spawn({
            let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);
            let shared_room_id = Arc::clone(&shared_room_id);
            let shared_url = Arc::clone(&shared_url);

            move || loop {
                let room_id_locked = shared_room_id.lock().unwrap().clone();
                let url_locked = shared_url.lock().unwrap().clone();

                match receive_and_fetch_messages(
                    &room_id_locked,
                    &shared_hybrid_secret,
                    &url_locked,
                    true,
                ) {
                    Ok(_) => {}
                    Err(e) => eprintln!("Error fetching messages: {}", e),
                }

                thread::sleep(Duration::from_secs(10));
            }
        });

        let rt = rocket::tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let app = MessagingApp::new(
                username,
                shared_hybrid_secret,
                Arc::clone(&shared_room_id),
                Arc::clone(&shared_url),
            );

            if let Err(e) = create_rocket(app).launch().await {
                eprintln!("Rocket server failed: {}", e);
            }
        });

        random_data_thread.join().ok();
        fetch_thread.join().ok();
        return Ok(());
    }

    let dilithium_keys = key_operations_dilithium(&sigalg, &username, &private_password);
    let Ok((dilithium_pk, dilithium_sk)) = dilithium_keys else { todo!() };

    let eddsa_keys = key_operations_eddsa(&username, &private_password);
    let Ok((eddsa_sk, eddsa_pk)) = eddsa_keys else { todo!() };

    let encoded_dilithium_pk = hex::encode(&dilithium_pk);
    send_dilithium_pubkey(&room_id, &encoded_dilithium_pk, &url);

    let encoded_eddsa_pk = hex::encode(&eddsa_pk);
    send_eddsa_pubkey(&room_id, &encoded_eddsa_pk, &url);

    let fingerprint_dilithium = fingerprint_dilithium_public_key(&dilithium_pk);

    println!("Own Dilithium5 fingerprint: {}", fingerprint_dilithium);

    let fingerprint_eddsa = match Ed25519PublicKey::from_bytes(&eddsa_pk) {
        Ok(public_key) => fingerprint_eddsa_public_key(&public_key),
        Err(e) => {
            eprintln!("Failed to convert EdDSA public key: {}", e);
            return Err(Box::new(e));
        }
    };

    println!("Own EdDSA fingerprint: {}", fingerprint_eddsa);

    let mut processed_fingerprints: HashSet<String> = HashSet::new();
    processed_fingerprints.insert(fingerprint_dilithium.clone());
    processed_fingerprints.insert(fingerprint_eddsa.clone());

    let mut all_other_dilithium_keys: Vec<oqs::sig::PublicKey> = Vec::new();

    while all_other_dilithium_keys.len() < 1 {
        println!("Waiting for Dilithium public key...");
        thread::sleep(Duration::from_secs(5));

        let encoded_other_dilithium_pks = fetch_dilithium_pubkeys(&room_id, &url);

        for encoded_pk in encoded_other_dilithium_pks {
            if let Ok(decoded_pk) = hex::decode(&encoded_pk) {

                let algorithm = SigAlgorithm::Dilithium5;

                let sig = Sig::new(algorithm).map_err(|_| "Failed to initialize signature scheme")?;

                if let Some(public_key_ref) = sig.public_key_from_bytes(&decoded_pk) {

                    let public_key = public_key_ref.to_owned();

                    let fetched_fingerprint = fingerprint_dilithium_public_key(&public_key);

                    if fetched_fingerprint == fingerprint_dilithium {
                        continue;
                    }

                    if processed_fingerprints.contains(&fetched_fingerprint) {
                        continue;
                    }

                    if request_user_confirmation(&fetched_fingerprint, &fingerprint_dilithium, &private_password)? {

                        all_other_dilithium_keys.push(public_key);
                        processed_fingerprints.insert(fetched_fingerprint);
                    } else {
                        eprintln!("User did not confirm the public key fingerprint.");
                    }
                } else {
                    eprintln!("Failed to decode valid public key.");
                }
            } else {
                eprintln!("Failed to convert decoded key to PublicKey.");
            }
        }
    }

    println!("Received Dilithium5 public key from the server.");

    let mut eddsa_key: Option<Ed25519PublicKey> = None;

    while eddsa_key.is_none() {
        println!("Waiting for EdDSA public key...");
        thread::sleep(Duration::from_secs(5));

        let encoded_other_eddsa_pks = fetch_eddsa_pubkeys(&room_id, &url);

        for encoded_pk in encoded_other_eddsa_pks {
            if let Ok(decoded_pk) = hex::decode(&encoded_pk) {
                if let Ok(public_key) = Ed25519PublicKey::from_bytes(
                    decoded_pk.as_slice().try_into().expect("Decoded public key must be 32 bytes long"),
                ) {
                    let fetched_fingerprint = fingerprint_eddsa_public_key(&public_key);

                    if fetched_fingerprint == fingerprint_eddsa {
                        continue;
                    }

                    if processed_fingerprints.contains(&fetched_fingerprint) {
                        continue;
                    }

                    if request_user_confirmation(&fetched_fingerprint, &fingerprint_eddsa, &private_password)? {
                        eddsa_key = Some(public_key);
                        processed_fingerprints.insert(fetched_fingerprint);
                        break;
                    } else {
                        eprintln!("User did not confirm the public key fingerprint.");
                    }
                } else {
                    eprintln!("Failed to decode valid public key.");
                }
            } else {
                eprintln!("Failed to convert decoded key to PublicKey.");
            }
        }
    }

    println!("Received EdDSA public key from the server.");

    let mut all_dilithium_pks = vec![dilithium_pk];
    all_dilithium_pks.extend(all_other_dilithium_keys);

    let kyber_shared_secret = kyber_key_exchange(&room_id, &all_dilithium_pks, &dilithium_sk, &url)?;
    let ecdh_shared_secret = if let Some(ref eddsa_key) = eddsa_key {
        perform_ecdh_key_exchange(&room_id, &eddsa_sk.to_bytes(), eddsa_key, &url)?
    } else {
        return Err("EdDSA public key is missing".into());
    };

    let hybrid_shared_secret = combine_shared_secrets(&kyber_shared_secret, &ecdh_shared_secret)?;

    println!("Hybrid shared secret established.");
    println!("You can now start messaging!");

let shared_hybrid_secret = Arc::new(hybrid_shared_secret.clone());
let shared_room_id = Arc::new(Mutex::new(room_id.clone()));
let shared_url = Arc::new(Mutex::new(url.clone()));

let random_data_thread = {
    let shared_room_id = Arc::clone(&shared_room_id);
    let shared_url = Arc::clone(&shared_url);
    let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);

    thread::spawn(move || loop {
        let mut random_data = vec![0u8; OsRng.next_u32() as usize % 2048 + 1];
        OsRng.fill_bytes(&mut random_data);

        let dummy_message = format!("[DUMMY_DATA]: {:?}", random_data);
        let padded_message = pad_message(&dummy_message, 2048);
        let encrypted_dummy_message = match encrypt_data(&padded_message, &shared_hybrid_secret) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Error encrypting dummy message: {}", e);
                continue;
            }
        };

        let room_id_locked = shared_room_id.lock().unwrap();
        let url_locked = shared_url.lock().unwrap();

        if let Err(e) = send_encrypted_message(&encrypted_dummy_message, &room_id_locked, &url_locked) {
            eprintln!("Error sending dummy message: {}", e);
        }

        thread::sleep(Duration::from_secs(OsRng.next_u32() as u64 % 120 + 1));
    })
};

let fetch_thread = thread::spawn({
    let shared_hybrid_secret = Arc::clone(&shared_hybrid_secret);
    let shared_room_id = Arc::clone(&shared_room_id);
    let shared_url = Arc::clone(&shared_url);

    move || loop {
        let room_id_locked = shared_room_id.lock().unwrap().clone();
        let url_locked = shared_url.lock().unwrap().clone();

        match receive_and_fetch_messages(
            &room_id_locked,
            &shared_hybrid_secret,
            &url_locked,
            true, 
        ) {
            Ok(_) => {}
            Err(e) => eprintln!("Error fetching messages: {}", e),
        }

        thread::sleep(Duration::from_secs(10));
    }
});

let rt = rocket::tokio::runtime::Runtime::new().unwrap();
rt.block_on(async {
    let app = MessagingApp::new(
        username,
        shared_hybrid_secret,
        Arc::clone(&shared_room_id),
        Arc::clone(&shared_url),
    );

    if let Err(e) = create_rocket(app).launch().await {
        eprintln!("Rocket server failed: {}", e);
    }
});

if let Err(e) = random_data_thread.join() {
    eprintln!("Random data thread terminated with error: {:?}", e);
}

if let Err(e) = fetch_thread.join() {
    eprintln!("Fetch thread terminated with error: {:?}", e);
}

    Ok(())
}    

fn clear_screen() {
    if cfg!(target_os = "windows") {
        Command::new("cmd")
            .args(&["/C", "cls"])
            .output()
            .expect("Failed to clear screen on Windows");
    } else {
        Command::new("clear")
            .status()
            .expect("Failed to clear screen on Unix");
    }
}
