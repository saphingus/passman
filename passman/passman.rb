require 'openssl'
require 'json'
require 'base64'
require 'highline/import'
require 'colorize'
require 'securerandom'
require 'fileutils'
require 'zxcvbn'
require 'tty-prompt'


$passfile = 'passwords.json'
$backupfile = 'passwords_backup.json'
$algorithm = 'aes-256-cbc'

# initialize TTY Prompt
prompt = TTY::Prompt.new

def clear
  system("clear") || system("cls")
end

def encrypt(text, key)
  cipher = OpenSSL::Cipher.new($algorithm).tap(&:encrypt)
  cipher.key = key
  iv = cipher.random_iv
  encrypted_data = cipher.update(text) + cipher.final
  { iv: Base64.encode64(iv), data: Base64.encode64(encrypted_data) }
end

def decrypt(enc_hash, key)
  decipher = OpenSSL::Cipher.new($algorithm).tap(&:decrypt)
  decipher.key = key
  decipher.iv = Base64.decode64(enc_hash[:iv])
  decrypted_data = decipher.update(Base64.decode64(enc_hash[:data])) + decipher.final
  decrypted_data
rescue OpenSSL::Cipher::CipherError
  puts "[ - ] error: decryption failed".colorize(:light_red)
  nil
end

def save_passwords(data)
  File.write($passfile, JSON.pretty_generate(data))
end

def load_passwords
  return [] unless File.exist?($passfile)
  JSON.parse(File.read($passfile), symbolize_names: true)
rescue JSON::ParserError
  puts "[ - ] error: file format is corrupted".colorize(:light_yellow)
  []
end

# Initialize the logger
logger = TTY::Logger.new

def get_master_password
  master_password = ask("[ * ] enter master password: ") { |q| q.echo = "*" }
  if master_password.empty?
    puts "[ - ] error: master password cannot be empty".colorize(:light_red)
    exit
  end
  master_password
end

def verify_master_password
  master_password = get_master_password
  key = OpenSSL::PKCS5.pbkdf2_hmac(master_password, "", 10000, 32, "sha256")
  key
end

def search_passwords(key)
  search_term = ask("[ * ] enter site to search: ")
  data = load_passwords
  results = data.select { |entry| entry[:site].include?(search_term) }
  if results.empty?
    puts "[ - ] no results found".colorize(:light_yellow)
  else
    results.each do |entry|
      decrypted_password = decrypt(entry[:encrypted_password], key)
      if decrypted_password
        puts "\n[ * ] site: #{entry[:site]}"
        puts "[ * ] username: #{entry[:username]}"
        puts "[ * ] password: #{decrypted_password}"
        puts "[ * ] category: #{entry[:category]}"
        puts "[------------------------------]"
      end
    end
  end
end

def generate_salt
  salt = OpenSSL::Random.random_bytes(16)
  encoded_salt = Base64.encode64(salt)
  puts "\n[ * ] salt: #{encoded_salt}".colorize(:light_green)
  encoded_salt
end

def show_dashboard
  data = load_passwords
  total_passwords = data.length
  file_size = File.size($passfile) rescue 0
  program_version = "1.0.0"
  encryption_status = check_encryption

  # Affichage minimaliste
  puts "\n[ * ] dashboard"
  puts "[========================================]".colorize(:white)
  puts "[ * ] program version: #{program_version}".colorize(:light_green)
  puts "[ * ] total passwords: #{total_passwords}".colorize(:light_blue)
  puts "[ * ] file zize: #{file_size} bytes".colorize(:light_cyan)
  puts "[ * ] encryption status: #{encryption_status}".colorize(:light_red)
  puts "[========================================]".colorize(:white)
end

def check_encryption
  encryption_enabled = true
  encryption_enabled ? "encrypted" : "not encrypted"
end

def generate_password
  # ask for the desired password length
  password_length = ask("[ * ] enter password length: ").to_i

  if password_length < 6
    puts "[ - ] error: password length must be at least 6 characters".colorize(:light_red)
    return
  end

  password = SecureRandom.base64(password_length)

  strength_report = check_password_strength(password)

  puts "\n[ * ] generated password: #{password}".colorize(:light_green)
  puts "[ * ] password strength: #{strength_report[:strength_level]}"
  puts "[ * ] score: #{strength_report[:score].to_s.colorize(:light_yellow)}/4"

  suggestions = Array(strength_report[:feedback]).compact

  case strength_report[:score]
  when 3, 4
    puts "[ - ] suggestions not found, password is strong enough".colorize(:light_red)
  else
    unless suggestions.empty?
      puts "[ * ] suggestions: consider generating a more complex password #{suggestions.join(', ').colorize(:light_magenta)}"
    else
      puts "[ - ] no suggestions available".colorize(:light_red)
    end
  end
end

def check_password_strength(password)
  result = Zxcvbn.test(password)

  # get password strength level
  strength_level = case result[:score]
                   when 0 then 'very weak'.colorize(:light_red)
                   when 1 then 'weak'.colorize(:light_yellow)
                   when 2 then 'fair'.colorize(:light_cyan)
                   when 3 then 'strong'.colorize(:light_green)
                   when 4 then 'very strong'.colorize(:light_blue)
                   else 'unknown'.colorize(:light_white)
                   end

  {
    score: result[:score],
    strength_level: strength_level,
    feedback: result[:feedback][:suggestions]
  }
end

def save_backup
  # ensure the backup directory exists
  backup_directory = "backups"
  FileUtils.mkdir_p(backup_directory) unless Dir.exist?(backup_directory)
  
  # generate a random backup filename
  backup_filename = generate_random_filename

  # create the backup file path
  backup_file_path = File.join(backup_directory, "#{backup_filename}.bak.json")
  
  # assuming 'data' holds the passwords and other sensitive info to backup
  data = load_passwords

  # save the backup in JSON format
  File.open(backup_file_path, 'w') do |file|
    file.write(JSON.pretty_generate(data))  # Converts the data to a pretty-printed JSON format
  end
  
  # Notify the user
  puts "[ * ] backup saved successfully as #{backup_filename}.bak.json".colorize(:light_green)
end

# Function to generate a random filename (lowercase, no periods, separated by commas)
def generate_random_filename
  random_string = SecureRandom.hex(10) # generates a 20-character hex string
  random_filename = random_string.tr('0-9a-f', 'a-z') # ensure it contains only lowercase letters
  random_filename.gsub!('.', '') # remove any periods if present (though `SecureRandom.hex` shouldn't generate them)
  random_filename.tr!('a-z', 'a-z'.split('').join(',')) # replace spaces with commas
  random_filename
end

def restore_backup
  prompt = TTY::Prompt.new
  backup_directory = "backups"  # Define your backup directory

  # Get all backup files (e.g., *.bak.json)
  backup_files = Dir.glob(File.join(backup_directory, "*.bak.json"))

  if backup_files.empty?
    puts "[ - ] no backup files found".colorize(:light_red)
    return
  end

  # Show list of backups using TTY::Prompt
  choice = prompt.select("\n[available backups]".colorize(:light_white), backup_files.map { |file| File.basename(file) }, per_page: 5)

  # Check if the user made a valid choice and restore the backup
  selected_backup = backup_files.find { |file| File.basename(file) == choice }
  if selected_backup
    data = JSON.parse(File.read(selected_backup))
    # Here you would overwrite your existing data with the restored backup
    puts "[ * ] backup restored from #{selected_backup}".colorize(:light_green)
    # Perform actual restoration of data here
  else
    puts "[ - ] invalid choice".colorize(:light_red)
  end
end

# define the backup menu using TTY with scroll and arrow key navigation
def backup_menu(prompt)
  loop do
    choice = prompt.select("\n[backup & restore]".colorize(:light_white), [
      'save backup of passwords'.colorize(:light_green),
      'restore backup of passwords'.colorize(:light_blue),
      'back to main menu'.colorize(:light_yellow)
    ], per_page: 3)  # per_page limits how many items are visible at once, scrollable with arrows

    case choice
    when 'save backup of passwords'.colorize(:light_green)
      save_backup  # call the save backup method
    when 'restore backup of passwords'.colorize(:light_blue)
      restore_backup(prompt)  # call the restore backup method
    when 'back to main menu'.colorize(:light_yellow)
      break  # go back to the main menu
    else
      puts "[ - ] invalid choice, try again".colorize(:light_red)
    end
  end
end

def show_password_tips
  tips = [
    "use at least 12 characters",
    "mix upper and lowercase letters",
    "include numbers and special characters",
    "avoid using personal info like birthdays",
    "use a password manager to generate and store complex passwords"
  ]
  puts "\n[ * ] password tips:".colorize(:light_blue)
  tips.each { |tip| puts " - #{tip}".colorize(:white) }
end

def delete_password(key)
  site = ask("[ * ] enter site to delete: ")
  data = load_passwords
  entry_to_delete = data.find { |entry| entry[:site] == site }
  if entry_to_delete
    data.delete(entry_to_delete)
    save_passwords(data)
    puts "\n[ * ] password for #{site} has been deleted".colorize(:light_red)
  else
    puts "[ - ] error: no entry found for #{site}".colorize(:light_yellow)
  end
end

# Define add_password method
def add_password(key)
  site = ask("[ * ] enter site: ")
  username = ask("[ * ] enter username: ")
  password = ask("[ * ] enter password: ") { |q| q.echo = "." }
  category = ask("[ * ] enter category: ")
  encrypted_password = encrypt(password, key)
  data = load_passwords
  data << { site: site, username: username, encrypted_password: encrypted_password, category: category }
  save_passwords(data)
  puts "\n[ * ] password for #{site} saved".colorize(:light_green)
end

# new advanced password analyzer
def advanced_password_analyzer
  password = ask("[ * ] enter password to analyze: ") { |q| q.echo = "." }
  entropy = password.length * Math.log2(password.length)

  puts "\n[ * ] analysis results for your password:".colorize(:light_blue)
  puts "[ * ] password length: #{password.length}".colorize(:light_cyan)
  puts "[ * ] password entropy: #{entropy.round(2)}".colorize(:light_yellow)

  if entropy < 40
    puts "[ * ] weak password entropy, try using a longer, more complex password".colorize(:light_red)
  else
    puts "[ * ] strong entropy, this password is more secure".colorize(:light_green)
  end
end

# submenu: password operations
def password_operations_menu(key)
  prompt = TTY::Prompt.new  # Define prompt here
  clear
  loop do
    choice = prompt.select("\n[password operations]".colorize(:white), [
      'add new password'.colorize(:light_green),
      'search for password'.colorize(:light_cyan),
      'delete password'.colorize(:light_red),
      'back to main menu'.colorize(:light_yellow)
    ], per_page: 4)

    case choice
    when 'add new password'.colorize(:light_green) then add_password(key)
    when 'search for password'.colorize(:light_cyan) then search_passwords(key)
    when 'delete password'.colorize(:light_red) then delete_password(key)
    when 'back to main menu'.colorize(:light_yellow) then break
    else puts "[ - ] invalid choice, try again".colorize(:light_red)
    end
  end
end

# submenu: tools & analysis
def tools_menu
  prompt = TTY::Prompt.new  # Define the prompt object
  clear
  loop do
    choice = prompt.select("\n[tools & analysis]".colorize(:white), [
      'generate random salt'.colorize(:light_blue),
      'generate random password'.colorize(:light_green),
      'advanced password analyzer'.colorize(:light_cyan),
      'back to main menu'.colorize(:light_yellow)
    ], per_page: 4)

    case choice
    when 'generate random salt'.colorize(:light_blue) then generate_salt
    when 'generate random password'.colorize(:light_green) then generate_password
    when 'advanced password analyzer'.colorize(:light_cyan) then advanced_password_analyzer
    when 'back to main menu'.colorize(:light_yellow) then break
    else puts "[ - ] invalid choice, try again".colorize(:light_red)
    end
  end
end

# submenu: backup operations
def backup_menu
  clear
  prompt = TTY::Prompt.new
  
  loop do
    choice = prompt.select("\n[backup & restore]".colorize(:light_white), [
      'save backup of passwords'.colorize(:light_green),
      'restore backup of passwords'.colorize(:light_blue),
      'back to main menu'.colorize(:light_yellow)
    ], per_page: 3)  # per_page limits how many items are visible at once, scrollable with arrows

    case choice
    when 'save backup of passwords'.colorize(:light_green)
      save_backup  # call the save backup method
    when 'restore backup of passwords'.colorize(:light_blue)
      restore_backup  # call the restore backup method
    when 'back to main menu'.colorize(:light_yellow)
      break  # go back to the main menu
    else
      puts "[ - ] invalid choice, try again".colorize(:light_red)
    end
  end
end

# submenu: info/help
def info_menu
  clear
  prompt = TTY::Prompt.new

  loop do
    choice = prompt.select("\n[info & help]".colorize(:white), [
      'show password tips'.colorize(:light_cyan),
      'show dashboard'.colorize(:light_green),
      'back to main menu'.colorize(:light_yellow)
    ], per_page: 3)  # scrollable list, only 3 items visible at a time

    case choice
    when 'show password tips'.colorize(:light_cyan)
      show_password_tips  # Call the method to show password tips
    when 'show dashboard'.colorize(:light_green)
      show_dashboard  # Call the method to show the dashboard
    when 'back to main menu'.colorize(:light_yellow)
      break  # Exit the loop and return to the main menu
    else
      puts "[ - ] invalid choice, try again".colorize(:light_red)
    end
  end
end

def main_menu
  clear
  # Display the ASCII art logo as part of the main menu
  puts "#{'88""Yb    db    .dP"Y8 .dP"Y8 8b    d8    db    88b 88'.colorize(:light_cyan)}"
  puts "#{'88__dP   dPYb   `Ybo." `Ybo." 88b  d88   dPYb   88Yb88'.colorize(:light_green)}"
  puts "#{'88"""   dP__Yb  o.`Y8b o.`Y8b 88YbdP88  dP__Yb  88 Y88'.colorize(:light_yellow)}"
  puts "#{'88     dP""""Yb 8bodP\' 8bodP\' 88 YY 88 dP""""Yb 88  Y8'.colorize(:light_red)}"
  puts "[========================================]"
  
  prompt = TTY::Prompt.new
  choice = prompt.select("", [
    'password operations'.colorize(:light_green),
    'tools & analysis'.colorize(:light_cyan),
    'backup & restore'.colorize(:light_yellow),
    'info & help'.colorize(:light_blue),
    'quit'.colorize(:light_red)
  ], per_page: 5)
  
  return choice
end

# main execution
master_key = verify_master_password
loop do
  choice = main_menu
  
  case choice
  when 'password operations'.colorize(:light_green)
    password_operations_menu(master_key)
  when 'tools & analysis'.colorize(:light_cyan)
    tools_menu
  when 'backup & restore'.colorize(:light_yellow)
    backup_menu
  when 'info & help'.colorize(:light_blue)
    info_menu
  when 'quit'.colorize(:light_red)
    puts "\n[ * ] goodbye!".colorize(:light_red)
    clear  # clear the screen first
    exit   # then exit the program
  else
    puts "[ - ] invalid choice, try again".colorize(:light_red)
  end
end
