require 'openssl'
require 'json'
require 'base64'
require 'highline/import'
require 'colorize'
require 'securerandom'
require 'fileutils'

# new ascii header
header = <<~HEADER
  #{'88""Yb    db    .dP"Y8 .dP"Y8 8b    d8    db    88b 88'.colorize(:light_cyan)}
  #{'88__dP   dPYb   `Ybo." `Ybo." 88b  d88   dPYb   88Yb88'.colorize(:light_green)}
  #{'88"""   dP__Yb  o.`Y8b o.`Y8b 88YbdP88  dP__Yb  88 Y88'.colorize(:light_yellow)}
  #{'88     dP""""Yb 8bodP\' 8bodP\' 88 YY 88 dP""""Yb 88  Y8'.colorize(:light_red)}
HEADER

puts header

$passfile = 'passwords.json'
$backupfile = 'passwords_backup.json'
$algorithm = 'aes-256-cbc'

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

def get_master_password
  master_password = ask("[ * ] enter master password: ") { |q| q.echo = "." }
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
  puts "[ * ] program version: #{program_version}"
  puts "[ * ] total passwords: #{total_passwords}"
  puts "[ * ] file zize: #{file_size} bytes"
  puts "[ * ] encryption status: #{encryption_status}"
  puts "[========================================]".colorize(:white)
end

# Placeholder pour vérifier l'encryption
def check_encryption
  # Exemple d'activation d'encryption
  encryption_enabled = true
  encryption_enabled ? "encrypted" : "not encrypted"
end

def generate_password
  password_length = ask("[ * ] enter password length: ").to_i
  if password_length < 6
    puts "[ - ] error: password length must be at least 6 characters".colorize(:light_red)
    return
  end
  password = SecureRandom.alphanumeric(password_length)
  puts "\n[ * ] generated password: #{password}".colorize(:light_green)
end

def test_password_strength
  password = ask("[ * ] enter password to test: ") { |q| q.echo = "." }
  score = 0
  score += 1 if password =~ /[A-Z]/
  score += 1 if password =~ /[a-z]/
  score += 1 if password =~ /[0-9]/
  score += 1 if password =~ /[\W_]/  # special characters
  score += 1 if password.length >= 12

  puts "\n[ * ] strength score: #{score}/5".colorize(:cyan)
  case score
  when 5 then puts "[ * ] password is very strong".colorize(:green)
  when 4 then puts "[ * ] password is strong".colorize(:light_green)
  when 3 then puts "[ * ] password is decent".colorize(:yellow)
  when 2 then puts "[ * ] password is weak".colorize(:light_red)
  else puts "[ * ] password is very weak".colorize(:red)
  end
end

def save_backup
  # Ensure the backup directory exists
  backup_directory = "backups"
  FileUtils.mkdir_p(backup_directory) unless Dir.exist?(backup_directory)
  
  # Generate a random backup filename
  backup_filename = generate_random_filename

  # Create the backup file path
  backup_file_path = File.join(backup_directory, "#{backup_filename}.bak.json")
  
  # Assuming 'data' holds the passwords and other sensitive info to backup
  data = load_passwords

  # Save the backup in JSON format
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
  backup_directory = "backups"
  backup_files = Dir.glob(File.join(backup_directory, "*.bak.json"))

  if backup_files.empty?
    puts "[ - ] no backup files found".colorize(:light_red)
    return
  end

  puts "[ * ]  available backups:"
  backup_files.each_with_index do |file, index|
    puts "[ #{index + 1} ] #{File.basename(file)}"
  end

  # Ask the user to select a backup file
  choice = ask("[ * ] select a backup to restore (number): ").to_i
  if choice > 0 && choice <= backup_files.length
    selected_backup = backup_files[choice - 1]
    data = JSON.parse(File.read(selected_backup))

    # Here you would overwrite your existing data with the restored backup
    puts "[ * ] backup restored from #{selected_backup}".colorize(:light_green)
    # Perform actual restoration of data here
  else
    puts "[ - ] invalid choice".colorize(:light_red)
  end
end

# Submenu for backup and restore operations
def backup_menu
  loop do
    puts "\n[backup & restore]".colorize(:light_magenta)
    puts "[ [1] ] save backup of passwords".colorize(:light_green)
    puts "[ [2] ] restore backup of passwords".colorize(:light_blue)
    puts "[ [3] ] back to main menu".colorize(:light_yellow)
    choice = ask("[ * ] select an option: ").to_i

    case choice
    when 1 then save_backup   # Save a backup
    when 2 then restore_backup  # Restore a backup
    when 3 then break  # Go back to the main menu
    else 
      puts "[ - ] invalid choice, try again".colorize(:light_red)
    end
  end
end

# Placeholder function for ask input
def ask(prompt)
  print prompt
  gets.chomp
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

# new advanced password analyzer
def advanced_password_analyzer
  password = ask("[ * ] enter password to analyze: ") { |q| q.echo = "." }
  entropy = password.length * Math.log2(password.length)

  puts "\n[ * ] analysis results for your password:".colorize(:light_blue)
  puts "[ * ] password length: #{password.length}".colorize(:cyan)
  puts "[ * ] password entropy: #{entropy.round(2)}".colorize(:yellow)

  if entropy < 40
    puts "[ * ] weak password entropy, try using a longer, more complex password".colorize(:light_red)
  else
    puts "[ * ] strong entropy, this password is more secure".colorize(:light_green)
  end
end

# submenu: password operations
def password_operations_menu(key)
  loop do
    puts "\n[password operations]".colorize(:light_magenta)
    puts "[ [1] ] add new password".colorize(:green)
    puts "[ [2] ] search for password".colorize(:cyan)
    puts "[ [3] ] delete password".colorize(:red)
    puts "[ [4] ] back to main menu".colorize(:light_yellow)
    choice = ask("[ * ] select an option: ").to_i
    case choice
    when 1 then add_password(key)
    when 2 then search_passwords(key)
    when 3 then delete_password(key)
    when 4 then break
    else puts "[ - ] invalid choice, try again".colorize(:light_red)
    end
  end
end

# submenu: tools & analysis
def tools_menu
  loop do
    puts "\n[tools & analysis]".colorize(:light_magenta)
    puts "[ [1] ] generate random salt".colorize(:blue)
    puts "[ [2] ] generate random password".colorize(:yellow)
    puts "[ [3] ] test password strength".colorize(:light_red)
    puts "[ [4] ] advanced password analyzer".colorize(:light_cyan)
    puts "[ [5] ] back to main menu".colorize(:light_yellow)
    choice = ask("[ * ] select an option: ").to_i
    case choice
    when 1 then generate_salt
    when 2 then generate_password
    when 3 then test_password_strength
    when 4 then advanced_password_analyzer
    when 5 then break
    else puts "[ - ] invalid choice, try again".colorize(:light_red)
    end
  end
end

# submenu: backup operations
def backup_menu
  loop do
    puts "\n[backup & restore]".colorize(:light_magenta)
    puts "[ [1] ] save backup of passwords".colorize(:light_green)
    puts "[ [2] ] restore backup of passwords".colorize(:light_blue)
    puts "[ [3] ] back to main menu".colorize(:light_yellow)
    choice = ask("[ * ] select an option: ").to_i
    case choice
    when 1 then save_backup
    when 2 then restore_backup
    when 3 then break
    else puts "[ - ] invalid choice, try again".colorize(:light_red)
    end
  end
end

# submenu: info/help
def info_menu
  loop do
    puts "\n[info & help]".colorize(:light_magenta)
    puts "[ [1] ] show password tips".colorize(:light_cyan)
    puts "[ [2] ] show dashboard".colorize(:green)
    puts "[ [3] ] back to main menu".colorize(:light_yellow)
    choice = ask("[ * ] select an option: ").to_i
    case choice
    when 1 then show_password_tips
    when 2 then show_dashboard
    when 3 then break
    else puts "[ - ] invalid choice, try again".colorize(:light_red)
    end
  end
end

# new main menu
def main_menu
  puts "\n[========================================]"
  puts "[password manager]".center(40).colorize(:light_magenta)
  puts "[========================================]"
  puts "[ [1] ] password operations".colorize(:green)
  puts "[ [2] ] tools & analysis".colorize(:cyan)
  puts "[ [3] ] backup & restore".colorize(:yellow)
  puts "[ [4] ] info & help".colorize(:blue)
  puts "[ [5] ] quit".colorize(:light_red)
end

# main execution
master_key = verify_master_password
loop do
  main_menu
  choice = ask("[ * ] select a category: ").to_i
  case choice
  when 1 then password_operations_menu(master_key)
  when 2 then tools_menu
  when 3 then backup_menu
  when 4 then info_menu
  when 5
    puts "\n[ * ] goodbye!".colorize(:light_red)
    exit
  else
    puts "[ - ] invalid choice, try again".colorize(:light_red)
  end
end

