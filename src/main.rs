use clap::Parser;
use ctrlc;
use netdev;
//use rumqttc::{MqttOptions, Client, QoS};
use comfy_table::{Table, Row, Cell};
use std::process::exit;
use std::{ io, str, thread};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use socket2::{Domain, Socket, Type, InterfaceIndexOrAddress};
use log::{debug, error, info, LevelFilter};
use simple_logger::SimpleLogger;
// use std::time::Duration;


const HDRSEP : &str = "\r\n";
const SVCPORT: u16 = 5090;
const MCGROUP: &str = "224.0.1.75";
const MCPORT : u16 = 5060;

#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum Mode {
    /// Nessun deubg
    #[default]
    Off,
    /// Livello debug base
    Info,
    /// Livello debug avanzato 
    Debug,
} 


#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Uri del server di provision 
    #[arg(short, long, default_value="https://prov.magaldinnova.it/provision")]
    uri: String,

    /// Interfaccia di rete da utilizzare, usa opzione -l o --list per ottenere la lista di interfacce
    #[arg(short, long)]
    intf: Option <u8>,

    /// Lista interfaccie di rete
    #[arg(short, long)]
    list: bool,

    /// Livello di debug
    #[arg(short, long, value_enum)]
    debug: Option<Mode>,
    
}

// Creazione di un oggetto tipo "classe" utilizzando Rust:
// Struttura dati + Trait + Implementazione del Trait
// Questa "classe base" conterrà i valori utilizzati per generare i singoli threads di risposta

struct MyThrValues {
    name: String,
    pktrcv: Vec<u8>,
    phone: (String, u16),
    hdrs: HashMap<String, String>,
    pnp_uri: String, 
    my_ip: String,
}

trait MyThr {
   fn crea(name: String, pkt: Vec<u8>, sender_ip_addr: (String, u16 ), cfg_server: &str, my_ip: &str ) -> Self;
   fn load_hdrs(&mut self);
   fn msg_ok(&self) -> String;
   fn msg_notify(&self) -> String;
   fn send_dgram(&mut self, pkt: String, w_flag: bool);
}

 
impl MyThr for MyThrValues {

    fn crea ( name: String, pkt: Vec<u8>, sender_ip_addr: (String, u16), cfg_server: &str, my_ip: &str ) -> MyThrValues {
        MyThrValues {
          name,
          pktrcv : pkt,
          phone: sender_ip_addr,
          hdrs: HashMap::new(),
          pnp_uri: String::from(cfg_server),
          my_ip: String::from(my_ip),
        } 
    } 

    // Legge il contenuto del pacchettoo VoIP e lo separa in un array di Headers
    fn load_hdrs(&mut self) {

        for hdr in str::from_utf8(&self.pktrcv).unwrap().split(HDRSEP) {
            if let Some((key, _value)) = hdr.split_once(':') {
                self.hdrs.insert(key.to_string(), hdr.to_string());
            }
        }

       debug!("Thread: {}, Headers ricevuti \n---------\n{:?}\n---------\n", self.name, self.hdrs); 
    }

    // Crea un messaggio HTTP di OK da inviare al dispositivo
    fn msg_ok(&self) -> String {

	    let mut msg = String::new();

        msg.push_str( &(format!("SIP/2.0 200 OK{}",HDRSEP))[..] ) ;
	    msg.push_str( self.hdrs.get("Via").expect(""));
	    msg.push_str( HDRSEP );
	    msg.push_str( &(format!("Contact: <sip:{}:{}>{}",self.phone.0,self.phone.1,HDRSEP))[..]);
	    msg.push_str( &(format!("{}{}",self.hdrs.get("To").expect(""),HDRSEP))[..]);
	    msg.push_str( &(format!("{}{}",self.hdrs.get("From").expect(""),HDRSEP))[..]);
	    msg.push_str( &(format!("{}{}",self.hdrs.get("Call-ID").expect(""),HDRSEP))[..]);
	    msg.push_str( &(format!("{}{}",self.hdrs.get("CSeq").expect(""),HDRSEP))[..]);
        msg.push_str( &(format!("{}{}",self.hdrs.get("Expires").expect(""),HDRSEP))[..]);
        msg.push_str( &(format!("{}{}",self.hdrs.get("Content-Length").expect(""),HDRSEP))[..]);
        
        info!("Thread: {}, Invio msg OK", self.name); 
        debug!("Thread: {}, MSG OK \n---------\n{}\n---------\n", self.name, msg); 

	    msg
    }

    // Crea un messaggio tipo SIP NOTIFY con i parametri necessari al dispostivo
    fn msg_notify(&self) -> String {
        
        let cseq_hval = self.hdrs.get("CSeq").unwrap();
        let x = cseq_hval.split(':').nth(1).unwrap().trim();
        let cseq_value = x.split(' ').nth(0).unwrap().parse::<i32>().unwrap() + 1;

        debug!("Thread: {}, CSEQ NEW VALUE -> {}", self.name, cseq_value); 

	    let mut msg = String::new();
      
        msg.push_str( &(format!("NOTIFY {}:{} SIP/2.0{}",self.phone.0, self.phone.1,HDRSEP))[..] ) ;
	    msg.push_str( self.hdrs.get("Via").expect(""));
	    msg.push_str( HDRSEP );
        msg.push_str( &(format!("Max-Forwards: 20{}",HDRSEP))[..] ) ;
        msg.push_str( &(format!("Contact: <sip:{}:{}>{}",self.phone.0,SVCPORT,HDRSEP))[..] ) ;
	    msg.push_str( self.hdrs.get("To").expect(""));
	    msg.push_str( HDRSEP );
	    msg.push_str( self.hdrs.get("From").expect(""));
	    msg.push_str( HDRSEP );
	    msg.push_str( self.hdrs.get("Call-ID").expect(""));
	    msg.push_str( HDRSEP );
        msg.push_str( &(format!("CSeq: {} NOTIFY{}",cseq_value,HDRSEP))[..] ) ;
        msg.push_str( &(format!("Content-Type: application/url{}",HDRSEP))[..] ) ;
        msg.push_str( &(format!("Subscription-State: terminated;reason=timeout{}",HDRSEP))[..] ) ;
        msg.push_str( &(format!("Event: ua-profile;profile-type=\"device\";vendor=\"OEM\";model=\"OEM\";version=\"1.0.0\"{}",HDRSEP))[..] ) ;
        msg.push_str( &(format!("Content-Length: {}{}{}",self.pnp_uri.len(),HDRSEP,HDRSEP))[..] ) ;
	    msg.push_str( &(self.pnp_uri)[..]);
     
        info!("Thread: {}, Invio msg NOTIFY", self.name); 
        debug!("Thread: {}, MSG NOTIFY\n---------\n{}\n---------\n", self.name, msg); 
        msg
    }

    // Crea un pacchetto UDP e lo spedisce al dispositivo che ne ha fatto richiesta
    fn send_dgram(&mut self, pkt: String, w_flag: bool) {

        let bnd_addr = &format!("{}:{}",self.my_ip,SVCPORT).parse::<SocketAddr>().unwrap().into();
        let dst_addr = &format!("{}:{}",self.phone.0,self.phone.1).parse::<SocketAddr>().unwrap().into();
        

        let s_snd = Socket::new( Domain::IPV4, Type::DGRAM, None).expect("Non posso creare s_snd");
        s_snd.set_reuse_address(true).unwrap();
        s_snd.set_nonblocking(false).unwrap();
        s_snd.set_read_timeout(Some(std::time::Duration::new(10, 0))).expect("Non posso impostare il timeout di s_snd");
        s_snd.bind(bnd_addr).unwrap();
        
        
        let _x = s_snd.send_to(pkt.as_bytes(), dst_addr).unwrap();
        info!("Thread: {}, -> invio DGRAM a {}:{}", self.name, self.phone.0, self.phone.1);

            if w_flag {

                let mut buf = Vec::with_capacity(4096);
                
                match s_snd.recv_from(buf.spare_capacity_mut()) {
                    Ok((size, _)) => {

                        unsafe {
                            buf.set_len(size);
                        }
        
                        let rsp = str::from_utf8(&buf[..size]).unwrap();
                        if rsp.contains("SIP/2.0 200") {
                            info!("Thread: {}, <- Ricevuto OK dal dispositivo [{}]", self.name, self.phone.0);
                        } else {
                            error!("Thread: {}, <- Errore, risposta inattesa.", self.name);
                        }
                    }
                    Err(e) => {
                        error!("Thread: {}, <- Errore, ho ricevuto: {}", self.name, e);
                    }
                }
            }

    }

}

fn select_default_if ( set_if:u32 ) -> (u32, String)  {
    
    let interfaces = netdev::get_interfaces();

    for interface in interfaces {
    
        if interface.default || interface.index == set_if {
            let x = interface.index;
            let addrs = interface.ipv4;
            let addr = addrs[0].addr().to_string();
            let mut dfl = "";
            if interface.default {
                dfl = "(default)"
            }

            if cfg!(windows) {
                debug!("Interfaccia selezionata: {}] {} {} IPv4: {}", x , interface.friendly_name.unwrap(), dfl,  addr);
            } 
            if cfg!(unix) {
                debug!("Interfaccia selezionata: {}] {} {} IPv4: {}", x , interface.name, dfl, addr);
            } 
            return (x, addr) ;
        }   
    }
    
    (0,"0.0.0.0".to_string())
    

}

fn show_net_if (){

    println!("\nElenco Interfacce:");

    let interfaces = netdev::get_interfaces();
    let mut table = Table::new();

    table
        .set_header(vec!["Indice", "Nome Int.", "Tipo Int.", "Ipv4", "Ipv6"]);
    
    for interface in interfaces {
    
        let mut row = Row::new();    
        let mut gtw_if;
    
        if interface.default {
            row.add_cell(Cell::new(format!("-> {}", interface.index)));
        } else {
            row.add_cell(Cell::new(format!("   {}", interface.index)));
        }
        
        gtw_if=interface.name;
    
        if cfg!(windows){
            gtw_if=interface.friendly_name.unwrap();      
        }

        row.add_cell(Cell::new(format!("{}", gtw_if)));
    
        row.add_cell(Cell::new(format!("{}", interface.if_type.name())));
        //if let Some(mac_addr) = interface.mac_addr {
        //    row.add_cell(Cell::new(format!("{}", mac_addr)));
        //}
        
        if interface.ipv4.len() > 0 {
            let mut x=String::new();
            for ip in interface.ipv4 {
                x.push_str((format!("{}\n",ip.addr().to_string())).as_str());
            }
            x.truncate(x.len() - 1);
            row.add_cell(Cell::new(x)); 
        }

        if interface.ipv6.len() > 0  {
            let mut y=String::new();
            for ip in interface.ipv6 {
                y.push_str((format!("{}\n",ip.addr().to_string())).as_str());
            }
            y.truncate(y.len() - 1);
            row.add_cell(Cell::new(y)); 
        }
        

        table.add_row(row);

        if let Some(gateway) = interface.gateway {
            
            let mut row = Row::new();    
        
            row.add_cell(Cell::new(""));
            row.add_cell(Cell::new(""));
            row.add_cell(Cell::new(format!("{} (Gateway) ",gtw_if.as_str())));
            //row.add_cell(Cell::new((format!("{}",gateway.mac_addr.to_string())).as_str())); 

            if gateway.ipv4.len() > 0 {
                let mut x=String::new();
                for ip in gateway.ipv4 {
                    x.push_str((format!("{}\n",ip.to_string())).as_str());
                }
                x.truncate(x.len() - 1);
                row.add_cell(Cell::new(x));
            }

            if gateway.ipv6.len() > 0 {
                let mut y=String::new();
                for ip in gateway.ipv6 {
                    y.push_str((format!("{}\n",ip.to_string())).as_str());
                }
                y.truncate(y.len() - 1);
                row.add_cell(Cell::new(y));
            }

            table.add_row(row);   
        } 
        
        /*println!("\tDNS {:?}", interface.dns_servers);
        println!(); */
        
    };
    println!("{table}");

}


fn main() -> io::Result<()> {
    
    let args = Args::parse();

    // shadowing ?
    let lev:LevelFilter;
    let ifx: u32;

    let cfg_srv: String = String::from(args.uri);

    if args.list {
        show_net_if();
        std::process::exit(0);
    }

    match args.debug {
        Some(Mode::Off) => {
           lev = LevelFilter::Off;
        }
        Some(Mode::Info) => {
            lev = LevelFilter::Info;
        }
        Some(Mode::Debug) => {
            lev = LevelFilter::Debug;
        }
        None => {
            lev = LevelFilter::Off;
        }
    }
 
    match args.intf {
        Some( val ) => { ifx = val.into() }
        None => { ifx = 0 } 
    }
    
    SimpleLogger::new()
        .with_level(LevelFilter::Off)
        .with_module_level("voipnp", lev)
        .init()
        .unwrap();

    ctrlc::set_handler(move || {
            println!("\nHo ricevuto un Ctrl+C ... esco ...\n");
            exit(0);
        })
        .expect("Error setting Ctrl-C handler");

    println!("");
    println!("VOIPNP - Voip PnP bootstrap provision server");
    println!("(C) 2025 - Mariano 'Qhawaq' Mancini");
    println!("----------------------------------------------------------------------------\n");
    
    if cfg!(unix){
        debug!("Sistema operativo: Unix/Linux");
    }

    if cfg!(windows){
        debug!("Sistema operativo: Windows");
    }

    let ifk = select_default_if(ifx);
    let def_if = ifk.0;
    let def_add = ifk.1;
    

    let s_mcast = Socket::new( Domain::IPV4, Type::DGRAM, None).expect("Impossibile creare il socket MCAST.");
    s_mcast.set_reuse_address(true)?;
    s_mcast.set_nonblocking(false)?;
 
    
    let group: Ipv4Addr = MCGROUP.parse().unwrap();

    if cfg!(windows){
        s_mcast.join_multicast_v4_n(&group, &InterfaceIndexOrAddress::Index(def_if))?;
        s_mcast.bind(&format!("{}:{}",def_add,MCPORT).parse::<SocketAddr>().unwrap().into())?;
    }

    if cfg!(unix) {
        s_mcast.join_multicast_v4(&group, &Ipv4Addr::new(0, 0, 0, 0))?;
        s_mcast.bind(&format!("0.0.0.0:{}",MCPORT).parse::<SocketAddr>().unwrap().into())?;
    }

    println!("Server avviato ... ");
    println!("In attesa ...");     

    /* TODO: Implementazione canale MQTT
    let mut mqttoptions = MqttOptions::new("rumqtt-sync", "test.mosquitto.org", 1883);
    mqttoptions.set_keep_alive(Duration::from_secs(5));

    let (mut client, mut connection) = Client::new(mqttoptions, 10);
    client.subscribe("hello/rumqtt", QoS::AtMostOnce).unwrap();

    thread::spawn(move || for i in 0..10 {
        client.publish("hello/rumqtt", QoS::ExactlyOnce, false, vec![i; i as usize]).unwrap();
        thread::sleep(Duration::from_millis(100));
     });
     
    for (i, notification) in connection.iter().enumerate() {
        println!("Notification = {:?}", notification);
    } */

    let mut thr_cnt = 0;

    loop {

        let def_ip = def_add.clone();
        let cfg = cfg_srv.clone();
        let mut buf = Vec::with_capacity(4096);

        match s_mcast.recv_from(buf.spare_capacity_mut()) {
            Ok((size, sender)) => {

                unsafe {
                    buf.set_len(size);
                }
      
                let addr = sender.as_socket_ipv4().unwrap();
                let snd_addr = addr.ip();
                let snd_port = sender.as_socket_ipv4().unwrap().port();    
                
                let snd_info = ( snd_addr.to_string(), snd_port);
                let thr_des = format!("Thr-{}-{}", thr_cnt, snd_addr).to_string(); 

                println!("Ricevuto un messaggio da {}", snd_addr); 
                info!("MainLoop, Ricevuto un MCAST da {}:{}", snd_addr, snd_port);

                thread::spawn(move || {

                    let voip_msg = &buf[..size];
                    let mut cur_thr: MyThrValues = MyThr::crea(thr_des, voip_msg.to_vec(), snd_info, cfg.as_str(), def_ip.as_str());
		            cur_thr.load_hdrs();
		            cur_thr.send_dgram(cur_thr.msg_ok(),false);
		            cur_thr.send_dgram(cur_thr.msg_notify(),true);

                });

                thr_cnt += 1;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Se è in timeout -> continua, se il socket è "non bloccante"
                continue;
            }
            Err(e) => {
                // La recv_from è entrata in panicking, loggo l'errore ed esco dal loop e termino il programma 
                error!("{}", e);
                break;
            }
        }

    } 

    Ok(())

}

