use std::sync::Arc;

use futures::executor;
use serde::{Deserialize, Deserializer};

use actix_web::{middleware::Logger, rt::System, web, App, HttpRequest, HttpResponse, HttpServer};
use openssl::rsa::Padding;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use rand::{distributions::Alphanumeric, Rng};

use prost::Message;

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use version_compare::Version;

use crate::dispatch::DispatchConfig;

#[derive(Clone, Default)]
pub struct DispatchServer {}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct ClientInfo {
    version: String,
    lang: i32,
    platform: i32,
    binary: i32,
    time: i32,
    channel_id: i32,
    sub_channel_id: i32,
    account_type: Option<i32>,
    key_id: Option<u8>,
}

#[derive(Deserialize, Debug)]
struct TokenToVerify {
    uid: String,
    token: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct ActionToCheck {
    action_type: String,
    api_name: String,
    username: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct LoginData {
    account: String,
    is_crypto: bool,
    password: String,
}
/*
#[derive(Deserialize,Debug)]
struct GranterData {
    app_id: String,
    channel_id: String,
    device: String,
    sign: String,
    data: String,
}*/

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct GranterData {
    #[serde(deserialize_with = "deserialize_u32_or_string")]
    app_id: u32,
    #[serde(deserialize_with = "deserialize_u32_or_string")]
    channel_id: u32,
    device: String,
    sign: String,
    data: String,
}

/* Deserialization hack */
fn deserialize_u32_or_string<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StrOrU32<'a> {
        Str(&'a str),
        U32(u32),
    }

    Ok(match StrOrU32::deserialize(deserializer)? {
        StrOrU32::Str(v) => v.parse().unwrap(), // Ignoring parsing errors
        StrOrU32::U32(v) => v,
    })
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct MinorApiLogData {
    data: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct GeetestGetData {
    gt: String,
    challenge: String,
    lang: String,
    is_next: Option<bool>,
    client_type: Option<String>,
    w: Option<String>,
    pt: Option<u32>,
    callback: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct GeetestGetTypeData {
    gt: String,
    t: u64,
    callback: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
struct GeetestAjaxData {
    gt: String,
    challenge: String,
    client_type: Option<String>,
    w: Option<String>,
    callback: Option<String>,
    #[serde(rename = "$_BBF")]
    bbf: Option<u32>,
}

impl DispatchServer {
    pub fn new() -> DispatchServer {
        DispatchServer::default()
    }

    pub fn run(self) {
        let mut _sys = System::new();
        let slef = Arc::new(self);
        executor::block_on(slef.run_internal());
        System::current().stop();
        println!("Finished!");
    }

    async fn run_internal(self: &Arc<Self>) {
        let config = DispatchConfig::load("dispatch_config.ini");

        //let (http_port, https_port) = (2880, 2443);
        println!(
            "Hostname {}, local IP {}",
            DispatchServer::get_hostname(),
            DispatchServer::get_local_ip()
        );

        let (http_port, https_port) = (config.http_port, config.https_port);

        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls_server()).unwrap();
        //builder.set_verify(SslVerifyMode::NONE);
        //builder.set_min_proto_version(None).unwrap();
        //builder.set_cipher_list("DEFAULT").unwrap();
        //builder.set_mode(SslMode::NO_AUTO_CHAIN | SslMode::SEND_FALLBACK_SCSV);
        builder
            .set_private_key_file(config.ssl_key.clone(), SslFiletype::PEM)
            .unwrap();
        builder
            .set_certificate_chain_file(config.ssl_cert.clone())
            .unwrap();

        let config = web::Data::new(config);

        HttpServer::new(move || {
            App::new()
                .app_data(config.clone())
                .wrap(Logger::default())
                .route("/", web::get().to(HttpResponse::Ok))
                .route(
                    "/query_security_file",
                    web::get().to(DispatchServer::query_security_file),
                )
                .route(
                    "/query_region_list",
                    web::get().to(DispatchServer::query_region_list),
                )
                .route(
                    "/query_cur_region/{region}",
                    web::get().to(DispatchServer::query_cur_region),
                )
                //.route("", web::post().to(DispatchServer::))
                .route(
                    "/hk4e_global/mdk/shield/api/verify",
                    web::post().to(DispatchServer::shield_verify),
                )
                //.route("/account/risky/api/check", web::post().to(DispatchServer::risky_api_check))
                .route(
                    "/account/risky/api/check",
                    web::post().to(DispatchServer::risky_api_check_old),
                )
                .route(
                    "/hk4e_global/mdk/shield/api/login",
                    web::post().to(DispatchServer::shield_login),
                )
                .route(
                    "/hk4e_global/combo/granter/login/v2/login",
                    web::post().to(DispatchServer::granter_login),
                )
                // Misc stuff, not really required
                .route(
                    "/common/h5log/log/batch",
                    web::post().to(DispatchServer::minor_api_log),
                )
                .route(
                    "/combo/box/api/config/sdk/combo",
                    web::get().to(DispatchServer::combo_combo),
                )
                .route(
                    "/hk4e_global/combo/granter/api/getConfig",
                    web::get().to(DispatchServer::get_config),
                )
                .route(
                    "/hk4e_global/mdk/shield/api/loadConfig",
                    web::get().to(DispatchServer::load_config),
                )
                //.route("/hk4e_global/combo/granter/api/getFont", web::get().to(DispatchServer::get_font))
                .route(
                    "/hk4e_global/mdk/agreement/api/getAgreementInfos",
                    web::get().to(DispatchServer::get_agreement_infos),
                )
                .route(
                    "/admin/mi18n/plat_oversea/m2020030410/m2020030410-version.json",
                    web::get().to(DispatchServer::version_data),
                )
                .route(
                    "/hk4e_global/combo/granter/api/compareProtocolVersion",
                    web::post().to(DispatchServer::compare_protocol_version),
                )
                // GEETEST
                .route("/get.php", web::get().to(DispatchServer::geetest_get))
                .route(
                    "/gettype.php",
                    web::get().to(DispatchServer::geetest_get_type),
                )
                .route("/ajax.php", web::get().to(DispatchServer::geetest_ajax_get))
                .route(
                    "/ajax.php",
                    web::post().to(DispatchServer::geetest_ajax_post),
                )
                // Logging
                .route("/log/sdk/upload", web::post().to(DispatchServer::log_skip))
                .route("/sdk/dataUpload", web::post().to(DispatchServer::log_skip))
                .route(
                    "/crash/dataUpload",
                    web::post().to(DispatchServer::log_skip),
                )
        })
        .bind(format!("0.0.0.0:{}", http_port))
        .expect("Failed to bind HTTP port")
        .bind_openssl(format!("0.0.0.0:{}", https_port), builder)
        .expect("Failed to bind HTTPS port")
        .run()
        .await
        .unwrap()
    }

    async fn query_security_file() -> String {
        "".to_string()
    }

    async fn query_region_list(
        c: web::Query<ClientInfo>,
        config: web::Data<DispatchConfig>,
    ) -> String {
        println!("RegionList, Client: {:?}", c);

        let keys = &config.client_secret_key;

        let regions_list = config
            .regions
            .iter()
            .map(|(r_name, r)| dispatch_proto::RegionSimpleInfo {
                name: r_name.clone(),
                title: r.title.clone(),
                r#type: r.r_type.clone(),
                dispatch_url: format!(
                    "http://{}:{}/query_cur_region/{}",
                    Self::get_local_ip(),
                    config.http_port,
                    r_name
                ),
            })
            .collect();

        let json_config = "{\"sdkenv\":\"2\",\"checkdevice\":\"false\",\"loadPatch\":\"false\",\"showexception\":\"false\",\"regionConfig\":\"pm|fk|add\",\"downloadMode\":\"0\"}";

        let mut custom_config = json_config.as_bytes().to_owned();

        mhycrypt::mhy_xor(&mut custom_config, &keys.xorpad);

        let region_list = dispatch_proto::QueryRegionListHttpRsp {
            region_list: regions_list,
            enable_login_pc: config.enable_login,
            client_secret_key: keys.ec2b.clone(),
            client_custom_config_encrypted: custom_config.to_vec(),
            ..Default::default()
        };
        let mut region_list_buf = Vec::new();

        region_list.encode(&mut region_list_buf).unwrap();

        base64::encode(region_list_buf)
    }

    async fn query_cur_region(
        req: HttpRequest,
        c: web::Query<ClientInfo>,
        config: web::Data<DispatchConfig>,
    ) -> String {
        println!("CurRegion, Client: {:?}", c);

        let region = req.match_info().get("region").unwrap();

        let first_rsa_version = Version::from("2.7.50").unwrap();
        let client_version = Self::get_clean_version(&c.0.version);
        let client_version = Version::from(&client_version).unwrap();

        let region = match config.regions.get(region) {
            Some(region) => region,
            None => panic!("Unknown region {}!", region),
        };

        let keys = &region.secret_key;

        let region_info = dispatch_proto::RegionInfo {
            gateserver_ip: region.gateserver_ip.clone(),
            gateserver_port: region.gateserver_port,
            secret_key: keys.ec2b.clone(),
            ..Default::default()
        };

        let json_config = format!("{{\"coverSwitch\": [\"8\"], \"perf_report_config_url\": \"http://{}:{}/config/verify\", \"perf_report_record_url\": \"http://{}:{}/dataUpload\" }}",
                                  DispatchServer::get_hostname(), config.http_port, DispatchServer::get_hostname(), config.http_port);

        let mut custom_config = json_config.as_bytes().to_owned();

        mhycrypt::mhy_xor(&mut custom_config, &keys.xorpad);

        let region_config = dispatch_proto::QueryCurrRegionHttpRsp {
            region_info: Some(region_info),
            client_secret_key: keys.ec2b.clone(),
            region_custom_config_encrypted: custom_config.to_vec(),
            ..Default::default()
        };

        let mut region_conf_buf = Vec::new();

        region_config.encode(&mut region_conf_buf).unwrap();

        if client_version >= first_rsa_version {
            let key_id = match c.0.key_id {
                Some(key_id) => key_id,
                None => panic!("Client version >= 2.7.50, but it haven't provided key_id!"),
            };

            let keys = match config.rsa_keys.get(&key_id) {
                Some(keys) => keys,
                None => panic!("Unknown key ID {}!", key_id),
            };

            const KEY_SIZE: usize = 256; // TODO: hardcoded constant!

            let mut out_buf: Vec<u8> = Vec::new();
            let mut enc_buf: Vec<u8> = vec![0; KEY_SIZE];

            for chunk in region_conf_buf.chunks((KEY_SIZE - 11) as usize) {
                // TODO: value hardcoded for the PKCS1 v1.5!
                let len = keys
                    .encrypt_key
                    .public_encrypt(chunk, &mut enc_buf, Padding::PKCS1)
                    .unwrap();
                out_buf.append(&mut enc_buf[0..len].to_vec());
                enc_buf.resize(KEY_SIZE, 0);
            }

            let keypair = PKey::from_rsa(keys.signing_key.clone()).unwrap();
            let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
            let signature = signer.sign_oneshot_to_vec(&region_conf_buf).unwrap();

            format!(
                "
            {{
                \"content\": \"{}\",
                \"sign\": \"{}\"
            }}
            ",
                base64::encode(out_buf),
                base64::encode(signature)
            )
        } else {
            base64::encode(region_conf_buf)
        }
    }

    async fn risky_api_check_old(a: web::Json<ActionToCheck>) -> String {
        println!("Action: {:?}", a);

        let email = "ceo@hoyolab.com";
        let name = "Ceo";
        let token = Self::generate_fake_token();
        let uid = 0x1234;

        let payload = DispatchServer::build_account_data(email, name, &token, uid);

        DispatchServer::make_answer(0, &payload)
    }

    #[allow(dead_code)]
    async fn risky_api_check(a: web::Json<ActionToCheck>) -> String {
        println!("Action: {:?}", a);

        let challenge = "5876e8bb6d90e0d6cf4dd26b109fe508";
        let gt = "16bddce04c7385dbb7282778c29bba3e";
        let id = "a0f5968aa4664b55ac914bffa1cd8058";

        let payload = format!(
            "
            {{
                \"action\": \"ACTION_GEETEST\",
                \"geetest\": {{
                    \"challenge\": \"{}\",
                    \"gt\": \"{}\",
                    \"new_captcha\": 1,
                    \"success\": 1
                }},
                \"id\": \"{}\"
            }}
        ",
            challenge, gt, id
        );

        DispatchServer::make_answer(0, &payload)
    }

    async fn shield_login(l: web::Json<LoginData>) -> String {
        println!("Login: {:?}", l);

        let email = "ceo@hoyolab.com";
        let name = "Ceo";
        let token = Self::generate_fake_token();
        let uid = 0x1234;

        let payload = DispatchServer::build_account_data(email, name, &token, uid);

        DispatchServer::make_answer(0, &payload)
    }

    async fn granter_login(g: web::Json<GranterData>) -> String {
        println!("Granter: {:?}", g);

        let payload = DispatchServer::verify_token_v2();

        DispatchServer::make_answer(0, &payload)
    }

    async fn combo_combo() -> String {
        let payload = "{{
            \"vals\": {{
                \"disable_email_bind_skip\": \"false\",
                \"email_bind_remind\": \"true\",
                \"email_bind_remind_interval\": \"7\"
            }}
        }}";

        DispatchServer::make_answer(0, payload)
    }

    async fn get_config() -> String {
        let payload = "{{
            \"announce_url\": \"https://localhost/hk4e/announcement/index.html\",
            \"disable_ysdk_guard\": false,
            \"enable_announce_pic_popup\": true,
            \"log_level\": \"INFO\",
            \"protocol\": true,
            \"push_alias_type\": 2,
            \"qr_enabled\": false
        }}";

        DispatchServer::make_answer(0, payload)
    }

    async fn load_config() -> String {
        let payload = "{{
            \"client\": \"PC\",
            \"disable_mmt\": false,
            \"disable_regist\": false,
            \"enable_email_captcha\": false,
            \"enable_ps_bind_account\": false,
            \"game_key\": \"hk4e_global\",
            \"guest\": false,
            \"id\": 6,
            \"identity\": \"I_IDENTITY\",
            \"ignore_versions\": \"\",
            \"name\": \"原神海外\",
            \"scene\": \"S_NORMAL\",
            \"server_guest\": false,
            \"thirdparty\": [
                \"fb\",
                \"tw\"
            ],
            \"thirdparty_ignore\": {{
                \"fb\": \"\",
                \"tw\": \"\"
            }}
        }}";
        DispatchServer::make_answer(0, payload)
    }

    async fn shield_verify(t: web::Json<TokenToVerify>) -> String {
        println!("Token: {:?}", t);

        let email = "ceo@hoyolab.com";
        let name = "Ceo";
        let token = t.token.clone();
        let uid = t.uid.parse().unwrap();

        let payload = DispatchServer::build_account_data(email, name, &token, uid);

        DispatchServer::make_answer(0, &payload)
    }

    async fn minor_api_log(_l: web::Json<MinorApiLogData>) -> String {
        "{\"retcode\":0,\"message\":\"success\",\"data\":null}".to_string()
    }

    /*
       GEETEST
    */
    async fn geetest_get(g: web::Query<GeetestGetData>) -> String {
        println!("GeetestGet: {:?}", g);

        let is_next = match g.is_next {
            None => false,
            Some(_) => true,
        };

        if is_next {
            let callback = g.callback.as_ref().unwrap();

            format!(
                "
                {}( {{
                    \"gt\": \"{}\",
                    \"challenge\": \"{}\",
                    \"id\": \"a7b56e21f6771ab10e2bc4a3a511c4be0\",
                    \"bg\": \"pictures/gt/1dce8a0cd/bg/744f986a0.jpg\",
                    \"fullbg\": \"pictures/gt/1dce8a0cd/1dce8a0cd.jpg\",
                    \"link\": \"\",
                    \"ypos\": 85,
                    \"xpos\": 0,
                    \"height\": 160,
                    \"slice\": \"pictures/gt/1dce8a0cd/slice/744f986a0.png\", \
                    \"api_server\": \"https://api-na.geetest.com/\",
                    \"static_servers\": [\"static.geetest.com/\", \"dn-staticdown.qbox.me/\"],
                    \"mobile\": true,
                    \"theme\": \"ant\",
                    \"theme_version\": \"1.2.6\",
                    \"template\": \"\",
                    \"logo\": false,
                    \"clean\": false,
                    \"type\": \"multilink\",
                    \"fullpage\": false,
                    \"feedback\": \"\",
                    \"show_delay\": 250,
                    \"hide_delay\": 800,
                    \"benchmark\": false,
                    \"version\": \"6.0.9\",
                    \"product\": \"embed\",
                    \"https\": true,
                    \"width\": \"100%\",
                    \"c\": [12, 58, 98, 36, 43, 95, 62, 15, 12],
                    \"s\": \"6b70592c\",
                    \"so\": 0,
                    \"i18n_labels\": {{
                        \"cancel\": \"Cancel\",
                        \"close\": \"Close\",
                        \"error\": \"Error. Close and retry.\",
                        \"fail\": \"Incorrect position\",
                        \"feedback\": \"Info\",
                        \"forbidden\": \"Retry after 3 seconds\",
                        \"loading\": \"Loading\",
                        \"logo\": \"Geetest\",
                        \"read_reversed\": false,
                        \"refresh\": \"Refresh\",
                        \"slide\": \"Slide to unlock\",
                        \"success\": \"sec s. You're better than score% of users\",
                        \"tip\": \"\",
                        \"voice\": \"Voice test\"
                    }},
                    \"gct_path\": \"/static/js/gct.d0a2919ae56f007ecb8e22fb47f80f33.js\"
                }} )",
                callback, g.gt, g.challenge
            )
        } else {
            let data = "
                ( {
                    \"status\": \"success\",
                    \"data\": {
                        \"theme\": \"wind\",
                        \"theme_version\": \"1.5.8\",
                        \"static_servers\": [\"static.geetest.com\", \"dn-staticdown.qbox.me\"],
                        \"api_server\": \"api-na.geetest.com\",
                        \"logo\": false,
                        \"feedback\": \"\",
                        \"c\": [12, 58, 98, 36, 43, 95, 62, 15, 12],
                        \"s\": \"3f6b3542\",
                        \"i18n_labels\": {
                            \"copyright\": \"Geetest\",
                            \"error\": \"Error\",
                            \"error_content\": \"Retry\",
                            \"error_title\": \"Timeout\",
                            \"fullpage\": \"Confirm\",
                            \"goto_cancel\": \"Cancel\",
                            \"goto_confirm\": \"OK\",
                            \"goto_homepage\": \"Go to Geetest homepage?\",
                            \"loading_content\": \"Confirm\",
                            \"next\": \"Loaging\",
                            \"next_ready\": \"Not fulfilled\",
                            \"read_reversed\": false,
                            \"ready\": \"Click to confirm\",
                            \"refresh_page\": \"Error. Refresh the page to continue.\",
                            \"reset\": \"Retry\",
                            \"success\": \"Success\",
                            \"success_title\": \"Success\"
                        }
                    }
                })
            ";

            match g.callback.as_ref() {
                None => data.to_string(),
                Some(callback) => format!("{}{}", callback, data),
            }
        }
    }

    async fn geetest_get_type(gt: web::Query<GeetestGetTypeData>) -> String {
        println!("GeetestGetType: {:?}", gt);

        let data = "\
            ( {
                \"status\": \"success\",
                \"data\": {
                    \"type\": \"fullpage\",
                    \"static_servers\": [\"static.geetest.com/\", \"dn-staticdown.qbox.me/\"],
                    \"click\": \"/static/js/click.3.0.2.js\",
                    \"pencil\": \"/static/js/pencil.1.0.3.js\",
                    \"voice\": \"/static/js/voice.1.2.0.js\",
                    \"fullpage\": \"/static/js/fullpage.9.0.8.js\",
                    \"beeline\": \"/static/js/beeline.1.0.1.js\",
                    \"slide\": \"/static/js/slide.7.8.6.js\",
                    \"geetest\": \"/static/js/geetest.6.0.9.js\",
                    \"aspect_radio\": {
                        \"slide\": 103, \"click\": 128, \"voice\": 128, \"pencil\": 128, \"beeline\": 50
                    }
                }
            })
        ";

        match &gt.callback {
            None => data.to_string(),
            Some(callback) => format!("{}{}", callback, data),
        }
    }

    async fn geetest_ajax_get(ga: web::Query<GeetestAjaxData>) -> String {
        Self::geetest_ajax(ga.into_inner()).await
    }

    async fn geetest_ajax_post(ga: web::Json<GeetestAjaxData>) -> String {
        Self::geetest_ajax(ga.into_inner()).await
    }

    async fn geetest_ajax(ga: GeetestAjaxData) -> String {
        println!("GeetestAjax: {:?}", ga);

        let is_next = match ga.bbf {
            None => false,
            Some(_) => true,
        };

        if is_next {
            let callback = ga.callback.as_ref().unwrap();

            format!(
                "
                {}( {{
                \"success\": 1,
                \"message\": \"success\",
                \"validate\": \"\",
                \"score\": \"11\"
            }} )",
                callback
            )
        } else {
            let data = "
                {
                    \"status\": \"success\",
                    \"data\": {
                        \"result\": \"slide\"
                    }
                }
            ";

            match ga.callback.as_ref() {
                None => data.to_string(),
                Some(callback) => format!(
                    "{}(
                        {}
                    )",
                    callback, data
                ),
            }
        }
    }

    async fn log_skip(body: web::Bytes) -> String {
        println!("Logging: {}", std::str::from_utf8(&body).unwrap());

        "{}".to_string()
    }

    async fn get_agreement_infos() -> String {
        let payload = "{{
            \"marketing_agreements\": []
        }}";

        DispatchServer::make_answer(0, payload)
    }

    async fn compare_protocol_version() -> String {
        let payload = "{{
            \"modified\": true,
            \"protocol\": {{
                \"app_id\": 4,
                \"create_time\": \"0\",
                \"id\": 0,
                \"language\": \"ru\",
                \"major\": 4,
                \"minimum\": 0,
                \"priv_proto\": \"\",
                \"teenager_proto\": \"\",
                \"user_proto\": \"\"
            }}
        }}";

        DispatchServer::make_answer(0, payload)
    }

    async fn version_data() -> String {
        "{\"version\": 54}".to_string()
    }

    fn get_hostname() -> String {
        hostname::get().unwrap().into_string().unwrap()
    }

    fn get_local_ip() -> String {
        "127.0.0.1".to_string()
    }

    fn get_clean_version(version: &str) -> String {
        let idx = version.chars().position(char::is_numeric).unwrap();

        version.chars().skip(idx).collect()
    }

    fn verify_token_v2() -> String {
        let account_type = 1;
        let combo_id = 0x4321;
        let open_id = 0x1234;

        #[cfg(not(feature = "raw_packet_dump"))]
        let combo_token = Self::generate_fake_token();
        #[cfg(feature = "raw_packet_dump")]
        let combo_token = std::str::from_utf8(&[32u8; 4096 * 3]).unwrap();

        format!(
            "{{
            \"account_type\": \"{}\",
            \"combo_id\": \"{}\",
            \"combo_token\": \"{}\",
            \"data\": {{\"guest\": \"false\"}},
            \"heartbeat\": false,
            \"open_id\": \"{}\"
        }}",
            account_type, combo_id, combo_token, open_id
        )
    }

    fn build_account_data(email: &str, name: &str, token: &str, uid: i32) -> String {
        format!(
            "{{
                \"account\": {{
                    \"apple_name\": \"\",
                    \"area_code\": \"**\",
                    \"country\": \"US\",
                    \"device_grant_ticket\": \"\",
                    \"email\": \"{}\",
                    \"facebook_name\": \"\",
                    \"game_center_name\": \"\",
                    \"google_name\": \"\",
                    \"identity_card\": \"\",
                    \"is_email_verify\": \"0\",
                    \"mobile\": \"\",
                    \"name\": \"{}\",
                    \"reactivate_ticket\": \"\",
                    \"realname\": \"\",
                    \"safe_mobile\": \"\",
                    \"sony_name\": \"\",
                    \"tap_name\": \"\",
                    \"token\": \"{}\",
                    \"twitter_name\": \"\",
                    \"uid\": \"{}\"
                }},
                \"device_grant_required\": \"false\",
                \"realperson_required\": \"false\",
                \"realname_operation\": \"None\",
                \"realperson_required\": false,
                \"safe_moblie_required\": \"false\"
            }}",
            email, name, token, uid
        )
    }

    fn make_answer(code: i32, data: &str) -> String {
        let message = match code {
            0 => "OK",
            -1 => "not matched",
            _ => "ERROR",
        };

        format!(
            "{{
            \"retcode\": \"{}\",
            \"message\": \"{}\",
            \"data\": {}
        }}",
            code, message, data
        )
    }

    fn generate_fake_token() -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }
}
