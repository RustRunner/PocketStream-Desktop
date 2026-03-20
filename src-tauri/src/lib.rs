mod camera;
mod commands;
mod config;
mod error;
mod network;
mod streaming;

pub use error::AppError;

pub fn run() {
    env_logger::init();

    // Initialize GStreamer once at startup
    gstreamer::init().expect("Failed to initialize GStreamer");
    log::info!("GStreamer {} initialized", gstreamer::version_string());

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(config::AppConfig::load_or_default())
        .manage(streaming::StreamManager::new())
        .manage(network::NetworkManager::new())
        .invoke_handler(tauri::generate_handler![
            // Config
            commands::get_config,
            commands::save_config,
            // Network
            commands::scan_network,
            commands::list_interfaces,
            commands::set_static_ip,
            commands::get_interface_info,
            // Streaming
            commands::start_stream,
            commands::stop_stream,
            commands::start_rtsp_server,
            commands::stop_rtsp_server,
            commands::get_stream_status,
            commands::take_screenshot,
            commands::start_recording,
            commands::stop_recording,
            // Video Embed
            commands::embed_video,
            commands::update_video_position,
            // Camera / PTZ
            commands::discover_onvif,
            commands::ptz_move,
            commands::ptz_stop,
            commands::ptz_goto_preset,
            commands::ptz_set_preset,
        ])
        .run(tauri::generate_context!())
        .expect("error while running PocketStream Desktop");
}
