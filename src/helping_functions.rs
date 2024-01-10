pub mod helping_functions{

    use std::io;

    use libc::priority_t;
pub fn test(pk: &mut [u8; 800], sk: &mut [u8; 1632])
{
    println!("Test");
}
    pub fn ask_general_yes_or_no(prompt: &str) -> bool {
        let mut input = String::new();

        loop {
            // Ask the user for input
            println!("{}", prompt);
            println!("Please enter (y)es or (n)o");//test git

            // Read user input
            io::stdin().read_line(&mut input).expect("Failed to read line");

            // Convert input to lowercase and trim whitespace
            let lowercase_input = input.trim().to_lowercase();

            match lowercase_input.as_str() {
                "y" | "yes" => {
                    println!("Input: 'yes'");
                    return true;
                }
                "n" | "no" => {
                    println!("Input: 'no'");
                    return false;
                }
                _ => {
                    // Handle invalid input
                    println!("Invalid input. Please enter (y)es or (n)o.");
                    input.clear();
                }
            }
        }
    }

    pub fn ask_for_number_question_integer(question: &str) -> u32
    {
        loop {
            //Print question
            println!("{}", question);
            
            //create value
            let mut input = String::new();
            
            //read response
            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read line");
    
            // Parse the input as a u32
            let parsed_input: Result<u32, _> = input.trim().parse();
            
            //verify
            match parsed_input {
                Ok(number) => {
                    return number;
                }
                Err(_) => {
                    println!("Invalid input. Please enter a valid number.");
                }
            }
        }
    }


    pub fn enter_a_password(correct_password: &str) -> i8 {
        let mut i = 3; 
    
        while i > 0 {
            println!("You have {} attempts", i);
            println!("Enter your password: ");
            
            let mut user_input = String::new();
            io::stdin().read_line(&mut user_input).expect("Failed to read input");
            
            let user_input = user_input.trim(); // Remove trailing newline
            if user_input.to_lowercase() == "l" || user_input.to_lowercase() == "leave"
                {
                    return 1;
                }
            if user_input == correct_password {
                return 0;
            }
            
            i -= 1; 
        }
    
        return -1;
    }
    pub fn hex_string_to_bytes(hex_string: &str) -> Option<Vec<u8>> {
        let hex_string_for_test = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
        // Check if the input string length is even (hexadecimal string should have pairs of characters)
        if hex_string.len() % 2 != 0 {
            return None;
        }
    
        // Try to parse each pair of characters into a u8 and collect them into a Vec<u8>
        let bytes: Result<Vec<u8>, _> = (0..hex_string_for_test.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_string_for_test[i..i + 2], 16))
            .collect();
    
        match bytes {
            Ok(bytes) => Some(bytes),
            Err(_) => None,
        }
    }


    pub fn get_seed_input() -> Vec<u8> {
        let mut input = String::new();
    
        loop {
            println!("Please input the hexadecimal seed string:");
            io::stdin().read_line(&mut input).expect("Failed to read line");
    
            let trimmed_input = input.trim();
    
            match hex_string_to_bytes(trimmed_input) {
                Some(bytes) => {
                    return bytes;
                }
                None => {
                    println!("Invalid hexadecimal seed string. Please try again.");
                    input.clear();
                }
            }
        }
    }
    
    pub fn get_a_password(prompt: &str) -> String {
        let mut input = String::new();
    
        loop {
            // Ask the user for input
            println!("{}", prompt);
    
            // Read user input
            io::stdin().read_line(&mut input).expect("Failed to read line");
    
            // Trim whitespace
            let trimmed_input = input.trim();
    
            // Check for strength
            if is_password_strong(trimmed_input) {
                return trimmed_input.to_string(); // Convert &str to String
            } else {
                println!("Sorry, that was not strong enough, please try again.");
            }
        }
    }

    pub fn get_security_strength() -> u32 {
        loop {
            println!("Choose a security strength (2, 3, or 4):");
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .expect("Failed to read line");

            // Parse the user's input as a u8
            match input.trim().parse::<u32>() {
                Ok(strength) => {
                    if [2, 3, 4].contains(&strength) {
                        return strength;
                    } else {
                        println!("Invalid input. Please enter 2, 3, or 4.");
                    }
                }
                Err(_) => {
                    println!("Invalid input. Please enter a number (2, 3, or 4).");
                }
            }
        }
    }
    pub fn is_password_strong(password: &str) -> bool {
        // Check if the password is at least 12 characters long
        if password.len() < 12 {
            return false;
        }
    
        // Check if the password contains at least one capital letter, one number, and one special character
        let mut has_capital = false;
        let mut has_number = false;
        let mut has_special = false;
    
        for c in password.chars() {
            if c.is_ascii_uppercase() {
                has_capital = true;
            } else if c.is_digit(10) {
                has_number = true;
            } else if !c.is_alphanumeric() {
                has_special = true;
            }
    
            // If all criteria are met, no need to continue checking
            if has_capital && has_number && has_special {
                return true;
            }
        }
    
        false
    }
}