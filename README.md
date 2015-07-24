# wpa_creat0r
 This is the backend of the WPA cracking exercise at TU Vienna (188.916 Introduction to Security)
 
 Students are required to break a WPA handshake. That handshake is created on the fly for each student via a webinterface, after entering their student-id.
 
 The final passphrase of the handshake (to be cracked) is the student-id concatenated with a randomly chosen password out of a supplied text file (password-file):<br />
 ```# Passphrase for WPA-handshake: student-ID plus random-PW```<br />
 ```voodoo = studentID + getRandomPW()```
