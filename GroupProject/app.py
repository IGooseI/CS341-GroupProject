

'''
Make sure to organize the files as follows:
phase1c (folder)
|__ app.py
|__ templates (folder)
|	|__ main.html
|	|__ login.html
|__ static (folder)
	|__ style.css


** The current username is roger, the password is roger123
'''

#import RPi.GPIO as GPIO
from gpiozero import LED
from signal import pause
from time import sleep
from flask import Flask, render_template, request, flash, redirect, session, url_for
import secrets
import smtplib
import emailcred
import hashlib
import random
from datetime import datetime
import hashpasswords
import json

try:
    # This creates an instance of a Flask application
    app = Flask(__name__)
    app.config['SECRET_KEY'] = secrets.token_urlsafe(16)    # read the NOTE below
    '''
    Note:
    1) app.config: This is a dictionary-like object used to store configuration settings for your Flask application.

    2) SECRET_KEY: This is a special configuration key in Flask, often used for securing sessions, cookies, 
    or other sensitive operations like CSRF (Cross-Site Request Forgery) protection. 
    The SECRET_KEY ensures that any data signed by your app (e.g., session cookies) cannot be tampered with by a client.

    3) secrets.token_urlsafe(16): This generates a secure, random string of 16 bytes encoded in a URL-safe format, 
    which is perfect for use as a cryptographic key. It ensures a high level of randomness and security.
    '''


    red_LED_GPIO = 23
    green_LED_GPIO = 24

    red_LED = LED(red_LED_GPIO) 
    green_LED = LED(green_LED_GPIO)
    
    # Number of Tries
    global tries
    tries = 3
    # In program timer for lockout time
    global lockout_time
    lockout_time = 15 # 300
    global OTP_code
    OTP_code = None

    try:
        stored_passwords = {"roger": hashpasswords.hash_password("roger123")}
        hashpasswords.password_store(stored_passwords)
    except Exception as e:
        print(f"Error storing passwords: {e}")
    # Create a dictionary called pins to store the pin number, name, and pin state:
    pins = {
       23 : {'var_name' : red_LED, 'state' : False, 'description' : 'The Red LED'},
       24 : {'var_name' : green_LED, 'state' : False, 'description' : 'The Green LED'}
       }

    # Assigne each pin as an LED and turn it off
    for pin in pins:
        led_name = pins[pin]['var_name']
        led_name.off()
    
    '''
    Note:
    1) session: In Flask, session is a special object used to store information about a user's session, 
    such as login status or preferences. 
    Data stored in session is unique to each user and typically backed by cookies or server storage. 
    Flask uses the SECRET_KEY (as we discussed earlier) to securely sign this data.

    2).get('logged_in'): The .get() method is used to retrieve the value associated with the key 'logged_in' from the session object. 
    If the key doesn't exist, it will return None by default (instead of raising an error).
    '''
    @app.route("/")
    def home():
        # This checks if the retrieved session value 'logged_in' is True
        if not session.get('lockedout'):
            return render_template('login.html')
        else:
            return render_template('lockedout.html')
        if not session.get('logged_in'):
            # if the 'logged_in' is not True, the user will be directed to the login.html page
            return render_template('login.html')
        else:
            #return "Hello Boss! <a href="/logout">Logout</a>"
            return render_template('main.html', **templateData)
    
    @app.route('/login', methods=['GET', 'POST'])
    def do_admin_login():
        global tries, lockout_time, OTP_code
        
        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')

            #Check credentials
            try:
                if username in stored_passwords:
                    hashed_password, salt = stored_passwords[username]
                    salted_password = password.encode() + bytes.fromhex(salt)
                    enter_hash = hashlib.sha256(salted_password).hexdigest()
                    
                    if enter_hash == hashed_password:
                        session['logged_in'] = True
                        tries = 3  # Reset tries
                        flash('Login successful!')
                        return redirect('/main')
                    else:
                        flash('Incorrect Password.')
                else:
                    flash('Username not Found')
            except Exception as e:
                flash(f"Error during Login: {e}")
                
            tries -= 1  # Decrement tries
            if tries > 0:
                flash(f"Incorrect Password or Username. Try Again. Tries Left: {tries}")
                return render_template('login.html')
                
            else:
                flash('Account locked. Please complete OTP Login.')
                print("System is Locked Out")
                return render_template('lockedout.html')

        return render_template('login.html')
    
            
                
                
    @app.route('/OTPLogin', methods=['GET','POST'])
    def OTPLogin():
        try:
            global lockout_time, OTP_code
            if session.get('lockedout', False):
                return render_template('lockedout.html')
            print("Accessing /OTPLogin route")
            if OTP_code is None or session.get('otp_attempted', False):
                print("Generating New OTP")
                OTP_code = random.randint(10000, 99999)
                send_msg(OTP_code)
                print(f"Your OTP code is: {OTP_code}") 
                print(f'The OTP Code has been sent to Email: {emailcred.TO}')
                
            entered_code2 = request.form.get('entered_code') # Note: Same as input command just requesting entered code from the HTML file space
            #entered_code2 = input("Enter the given code: ")
            #print(f"User Entered OTP: {entered_code2}")
            if entered_code2 == str(OTP_code):
                session['lockedout'] = False
                flash('2FA Code is Correct!! Please log in Again')
                #sleep(5)
                return render_template('login.html')
            else:
                #print("Invalid code")
                flash('Invalid OTP Code. Please Try Again.')
                    
            return render_template('OTPLogin.html')
                    
        except Exception as e:
            print(f"Error in /OTPLogin: {e}")
            flash("An error Occured.")
            return home()
            
    @app.route('/session-status')
    def session_status():
        if session.get('lockedout', True):
            return {'locked': session.get('lockedout', True)}
        else:
            return {'locked' : session.get('lockedout', False)}
        
          
    
    def send_msg(OTP_code):
        try:
            server = smtplib.SMTP_SSL( 'smtp.gmail.com', 465)
            server.login( emailcred.FROM, emailcred.PASS )
            actionMessage = ''.join([ f"\n Garage Door 2FA Code is: {OTP_code}"]) 
            print(actionMessage)
            server.sendmail(emailcred.FROM, emailcred.TO, actionMessage)
            server.quit()
        except Exception as e:
            print(f"Error Sending Email: {e}") 
     
    
    @app.route("/logout")
    def logout():
        # update the session value 'logged_in' to False
        session['logged_in'] = False
        session['lockedout'] = False

        tries = 3
        return home()
    
    @app.route("/userCreate", methods=['GET', 'POST'])
    def user_Create():
        render_template('userCreate.html')
        if request.method == 'POST':
            username = request.form.get('username', '')
            password = request.form.get('password', '')
            email = request.form.get('email', '')
        created_users = {"Username: " ,username , "Password: ", password, "Email: ", email}
        filePath = "users.json"
        with open(filePath, "rb") as file:
            users = json.dump(username, password, email)
        entered_username = "entered_username"
        entered_email = "entered_email"
        users.append(created_users)
        while True:
            if any(users(username)) == username:
                error_message = "There is Already a User with that Name. Please Enter Another"
            if any(users(email)) == email:
                error_message = "This Email is already linked with another account. Try a Different one"
        

            
        




        
    
    
    
    
    
    
    @app.route("/main")
    def main():
        # check if the user logged_in to the system
        if not session.get('logged_in'):
            return render_template('login.html')
        else:
            # For each pin, read the pin state and store it in the pins dictionary:
            for pin in pins:
                LED_name = pins[pin]['var_name']
                pins[pin]['state'] = LED_name.is_lit
                print("in main pin {pin} is: ", pins[pin]['state'])
              
            # Put the pin dictionary into the template data dictionary:
            templateData = {
              'pins' : pins
              }
            
            # Pass the template data into the template main.html and return it to the user
            return render_template('main.html', **templateData)

    # The function below is executed when someone requests a URL with the pin number and action in it:
    @app.route("/<changePin>/<action>")
    def action(changePin, action):
        if not session.get('logged_in'):
            return render_template('login.html')
        else:
            # Convert the pin from the URL into an integer:
            changePin = int(changePin)
            # Get the LED name for the pin being changed:
            LED_name = pins[changePin]['var_name']
            # If the action part of the URL is "on," execute the code indented below:
            if action == "on":
                # Set the pin high:
                LED_name.on()
                #print("the action is on for: ", LED_name)
                # Save the status message to be passed into the template:
                message = "Turned " + str(changePin) + " on."
            if action == "off":
                LED_name.off()
                print("the action is off for: ", LED_name)
                message = "Turned " + str(changePin) + " off."

            # For each pin, read the pin state and store it in the pins dictionary:
            for pin in pins:
                LED_name = pins[pin]['var_name']
                pins[pin]['state'] = LED_name.is_lit
                #print(f'pin number {pin} is', pins[pin]['state'])

            # Along with the pin dictionary, put the message into the template data dictionary:
            templateData = {
              'pins' : pins
            }

            return render_template('main.html', **templateData)

    # run Flask application
    if __name__ == "__main__":
        print("Enter Ctrl+C to exit.")
        app.run(host='0.0.0.0', port=80, debug=False)
        
except KeyboardInterrupt:
    # Handle Ctrl+C gracefully
    print("\nExiting the program...")

finally:
    # Cleanup resources
    print("Closing the Flask app.")
    print("Cleaning up GPIO pins...")
    red_LED.off()           # Ensure the red LED is turned off
    red_LED.close()         # Release the GPIO pin for the red LED
    green_LED.off()         # Ensure the green LED is turned off
    green_LED.close()       # Release the GPIO pin for the green LED
