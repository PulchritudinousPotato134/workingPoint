use crate::{kyber_rng::KyberRng as MyRng, helping_functions, kem};
use rand::Rng;


#[derive(Debug,Clone)]
pub struct KyberParams {
    pub kyber_k: u32,
    pub kyber_namespace: String,
    pub kyber_n: u32,
    pub kyber_q: u32,
    pub kyber_symbytes: u32,
    pub kyber_ssbytes: u32,
    pub kyber_polybytes: u32,
    pub kyber_polycompressedbytes: u32,
    pub kyber_polyvecbytes: u32,
    pub kyber_eta1: u32,
    pub kyber_polyveccompressedbytes: u32,
    pub kyber_eta2: u32,
    pub kyber_indcpa_msgbytes: u32,
    pub kyber_indcpa_publickeybytes: u32,
    pub kyber_indcpa_secretkeybytes: u32,
    pub kyber_indcpa_bytes: u32,
    pub kyber_publickeybytes: u32,
    pub kyber_secretkeybytes: u32,
    pub kyber_ciphertextbytes: u32,
}

impl KyberParams {
    pub fn set_parameters(security_level: u32) -> Option<KyberParams> {
        match security_level {
            2 => Some(KyberParams {
                kyber_k: 2,
                kyber_namespace: "pqcrystals_kyber512_ref".to_string(),
                kyber_n: 256,
                kyber_q: 3329,
                kyber_symbytes: 32,
                kyber_ssbytes: 32,
                kyber_polybytes: 384,
                kyber_polycompressedbytes: 128,
                kyber_eta1: 3,
                kyber_polyveccompressedbytes: 640,
                kyber_polyvecbytes: 768,
                kyber_eta2: 2,
                kyber_indcpa_msgbytes: 32,
                kyber_indcpa_publickeybytes: 800,
                kyber_indcpa_secretkeybytes: 768,
                kyber_indcpa_bytes: 768,
                kyber_publickeybytes: 800,
                kyber_secretkeybytes: 1632,
                kyber_ciphertextbytes: 768,
            }),
            3 => Some(KyberParams {
                kyber_k: 3,
                kyber_namespace: "pqcrystals_kyber768_ref".to_string(),
                kyber_n: 256,
                kyber_q: 3329,
                kyber_symbytes: 32,
                kyber_ssbytes: 32,
                kyber_polybytes: 384,
                kyber_polycompressedbytes: 128,
                kyber_eta1: 2,
                kyber_polyveccompressedbytes: 960,
                kyber_polyvecbytes: 1152,
                kyber_eta2: 2,
                kyber_indcpa_msgbytes: 32,
                kyber_indcpa_publickeybytes: 1184,
                kyber_indcpa_secretkeybytes: 1152,
                kyber_publickeybytes: 1184,
                kyber_secretkeybytes: 2400,
                kyber_indcpa_bytes: 1088,
                kyber_ciphertextbytes: 1088,
            }),
            4 => Some(KyberParams {
                kyber_k: 4,
                kyber_namespace: "pqcrystals_kyber1024_ref".to_string(),
                kyber_n: 256,
                kyber_q: 3329,
                kyber_symbytes: 32,
                kyber_ssbytes: 32,
                kyber_polybytes: 384,
                kyber_polycompressedbytes: 160,
                kyber_eta1: 2,
                kyber_polyvecbytes: 1536,
                kyber_polyveccompressedbytes: 1408,
                kyber_eta2: 2,
                kyber_indcpa_msgbytes: 32,
                kyber_indcpa_publickeybytes: 1568,
                kyber_indcpa_secretkeybytes: 1536,
                kyber_indcpa_bytes: 1568,
                kyber_publickeybytes: 1568,
                kyber_secretkeybytes: 3168,
                kyber_ciphertextbytes: 1568,
            }),
            _ => None, // Handle other security levels or return an error
        }
    }
}
#[derive(Debug,Clone)]
pub struct Kyber {
    pub params: KyberParams, 
    has_key_been_generated: bool,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    private_key_password: String,
}

impl Kyber {
        pub fn create(security_level: u32) -> Kyber 
        {
            let params = KyberParams::set_parameters(security_level).expect("Invalid security level");
    
            let mut kyber_instance = Kyber {
                params: params.clone(), // Assuming KyberParams implements Clone
                has_key_been_generated: false,
                public_key: Vec::new(),
                private_key: Vec::new(),
                private_key_password: String::new(),
            };
    
            kyber_instance
        }

    pub fn generate_random_bytes<T>(&mut self, use_rust_random: bool, num_bytes: T) -> Vec<u8>
    where
        T: Into<usize>
    {
        let num_bytes = num_bytes.into();
        let mut entropy_input = vec![0u8; num_bytes];
    
        if use_rust_random {
            let mut rng = rand::thread_rng();
            for i in 0..num_bytes {
                entropy_input[i] = rng.gen();
            }
        } else {
            for i in 0..num_bytes {
                entropy_input[i] = i as u8;
            }
        }
    
        let mut random_bytes = vec![0u8; num_bytes];
        {
            let mut rng = crate::GLOBAL_RANDOM.lock().unwrap();
            rng.randombytes(&mut random_bytes, num_bytes as u64);
        }



        random_bytes
    }




    fn do_generate_key_pair(&mut self) -> (Vec<u8>, Vec<u8>) 
    {
        // Generate random bytes for the private key
        let private_bytes = self.generate_random_bytes(true, self.params.kyber_secretkeybytes as usize);

        // Generate random bytes for the public key
        let public_bytes = self.generate_random_bytes(true, self.params.kyber_publickeybytes as usize);

        // Initialize empty vectors for public and private keys
        let mut private_key = vec![0u8; self.params.kyber_secretkeybytes as usize];
        let mut public_key = vec![0u8; self.params.kyber_publickeybytes as usize];

        // Call crypto_kem_keypair to generate the key pair
        kem::kem::crypto_kem_keypair(&mut public_key, &mut private_key).expect("Key pair generation failed");

        // Clone the keys for internal use
        self.private_key = private_key.clone();
        self.public_key = public_key.clone();

        // Return the generated keys as a tuple
        (public_key, private_key)
    }

    
    fn generate_outside_key_pair(&mut self, strength: u32) -> (Vec<u8>, Vec<u8>) 
    {
        let (private_bytes, public_bytes): (Vec<u8>, Vec<u8>);
        
        if strength == 2 {
            private_bytes = self.generate_random_bytes(true, 1632 as usize);
            public_bytes = self.generate_random_bytes(true, 800 as usize);
        } else if strength == 3 {
            private_bytes = self.generate_random_bytes(true, 1184 as usize);
            public_bytes = self.generate_random_bytes(true, 2400 as usize);
        } else if strength == 4 {
            private_bytes = self.generate_random_bytes( true, 1568 as usize);
            public_bytes = self.generate_random_bytes( true, 3168 as usize);
        } else {
            panic!("Invalid strength input");
        }
    
        let mut private_key = vec![0u8; self.params.kyber_secretkeybytes as usize];
        let mut public_key = vec![0u8; self.params.kyber_publickeybytes as usize];
        // Call crypto_kem_keypair to generate the key pair
        kem::kem::crypto_kem_keypair(&mut public_key, &mut private_key).expect("Key pair generation failed");
    
        // Return the generated keys as a tuple
        (public_key, private_key)
    }
    

    pub fn generate_key_pair(&mut self) 
    {
        if self.has_key_been_generated {
            let resp = helping_functions::helping_functions::ask_general_yes_or_no(
                "You have already generated a key pair.\nAre you sure you want to generate a new one?",
            );
            if resp {
                self.do_generate_key_pair();
                println!("New key pair generated!");
            } else {
                return;
            }
        } else {
            println!("Generating new key pair...");
            self.do_generate_key_pair();
            println!("New key pair generated!");
        }
    
        println!("The following keys have been generated:");
        println!("Public Key: {:?}", self.public_key);
        println!("Private Key: {:?}", self.private_key);
        println!("You can always use 'get_public_key()' to view the public key");
        println!("For the private key, however, we will require a 12 character passphrase.");
        println!("Please enter the passphrase now:");
        self.private_key_password =
            helping_functions::helping_functions::get_a_password("Please include at least 1 capital letter, 1 number and 1 special character.");
        println!("The password has been set.");
    }
    

    pub fn generate_external_key_pair(&mut self) -> (Vec<u8>, Vec<u8>) 
    {
        let (mut pub_key, mut priv_key);
    
        loop {
            let strength = helping_functions::helping_functions::ask_for_number_question_integer("What strength would you like (2, 3, or 4)?");
    
            if strength != 2 && strength != 3 && strength != 4 {
                println!("You have entered an invalid number, please try again.");
            } else {
                println!("Generating keys...");
                (pub_key, priv_key) = self.generate_outside_key_pair( strength);
                break;
            }
        }
    
        println!("The following keys have been generated:");
        println!("Public Key: {:?}", pub_key);
        println!("Private Key: {:?}", priv_key);
    
        (pub_key, priv_key)
    }
    

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, i32> 
    {

        Err(-1)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, i32> 
    {

        Err(-1)
    }

    pub fn get_private_key(&mut self) 
    {
        println!("The private key is protected.");
        println!("In order to see it, please enter your private key password:");
        println!("WARNING! If you enter your password incorrectly 3 times in a row, the key will be deleted!");
        println!("You can enter 'leave' at any time to exit without penalty");
    
        let resp = helping_functions::helping_functions::enter_a_password(&self.private_key_password);
        
        if resp == 1 {
            println!("You have correctly entered the password.");
            println!("Your private key is:");
            println!("Private Key: {:?}", self.private_key);
        } else if resp == -1 {
            println!("You have entered your password incorrectly too many times. The keys will be removed.");
            self.private_key.clear();
            self.public_key.clear();
            self.has_key_been_generated = false;
            self.private_key_password = "".to_string(); 
            println!("Keys removed.");
        } else {
            println!("Quitting...");
        }
    }
    
    pub fn get_public_key(&mut self)
    {
        println!("The public key is as follows.");
        println!("Public Key: {:?}", self.public_key);
    }

    pub fn test_encryption_with_seed(&mut self) {
        println!("Please enter the seed value:");
        let seed = helping_functions::helping_functions::get_seed_input();
        let ps: u8 = 0;

        let personalization_string: Option<Vec<u8>> = if ps == 0 {
            None
        } else {
            Some(vec![ps])
        };

        {
            let mut rng = crate::GLOBAL_RANDOM.lock().unwrap();
            rng.randombytes_init(seed, personalization_string, 256);
        }

        let mut private_key = vec![0u8; self.params.kyber_secretkeybytes as usize];
        let mut public_key = vec![0u8; self.params.kyber_publickeybytes as usize];
        kem::kem::crypto_kem_keypair(&mut public_key, &mut private_key).expect("Key pair generation failed");
        println!("Public Key: {:?}", public_key);
        println!("Private Key: {:?}", private_key);
    }
    
    
   /*/
    fn setPublicKey()
    fn setPrivateKey()
    fn importKey()
    fn exportKey(type)
    fn sign()
    fn verifySignature()
    fn generateRandomBytes()
    */
}
