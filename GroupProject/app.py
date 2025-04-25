

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
        stored_passwords = {"roger": hashpasswords.hash_password("roger123")}  # Assuming hash_password returns a single value
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
        if session.get('lockedout'):
            return render_template('lockedout.html')
        elif not session.get('logged_in'):
            # If the 'logged_in' is not True, the user will be directed to the login.html page
            return render_template('login.html')
        elif session.get('is_admin'):
            return render_template('main_admin.html')
        else:
            # Return the main page for non-admin users
            return render_template('main.html')
    
    @app.route('/login', methods=['GET', 'POST'])
    def do_admin_login():
        global tries
        filePath = "users.json"
        error_message = None
        if request.form['password'] == 'roger123' and request.form['username'] == 'roger':
            session['logged_in'] = True
            session['is_admin'] = True
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            print(f"Entered username: {username}")
            print(f"Entered password: {password}")

            # Check hardcoded credentials first
            if username == 'roger' and password == 'roger123':
                session['logged_in'] = True
                session['is_admin'] = True
                tries = 3
            # Check dynamically stored users in users.json
            try:
                with open(filePath, "r") as file:
                    users = json.load(file)

                # Find the user by username
                user = next((u for u in users if u['Username'] == username), None)
                if user:
                    hashed_password = user['Password']
                    salt = user['Salt']
                    if hashpasswords.verify_password(password, hashed_password, salt):
                        session['logged_in'] = True
                        session['username'] = username
                        session['is_admin'] = user.get('Admin', False)
                        tries = 3  # Reset tries
                        flash('Login successful!')
                        return redirect('/main')
                    else:
                        error_message = "Incorrect password."
                else:
                    error_message = "Username not found."

            except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
                error_message = "User database not found or corrupted. Please contact the admin."
                flash(error_message)
                print(error_message, {e})
                return render_template('login.html', error_message=error_message)

            # Handle failed login attempts only if username and password validation fails
            if error_message:
                tries -= 1
                if tries <= 0:
                    session['lockedout'] = True
                    flash('Too many failed attempts. Your account is locked.')
                    return redirect('/OTPLogin')  # Redirect to OTP login
                session['lockedout'] = True
                flash('Too many failed attempts. Your account is locked.')
                return redirect('/OTPLogin')  # Redirect to OTP login

            flash(f"{error_message} Tries remaining: {tries}")

        return render_template('login.html', error_message=error_message)


    
            
                
                
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
        session['is_admin'] = False

        tries = 3
        return home()
    
    def add_new_user(users, username, password, email, is_admin, filePath):
        print("add_new_user has been called")
        hashed_password, salt = hashpasswords.hash_password(password)
        users.append({
            'Username': username,
            'Password': hashed_password,
            'Salt': salt,
            'Email': email,
            'Admin': is_admin
        })
        
       
        with open(filePath, "w") as file:
            json.dump(users, file, indent=4)

        

    @app.route("/userCreate", methods=['GET', 'POST'])
    def userCreate():
        username = ""
        password = ""
        email = ""
        is_admin = False
        error_message = None
        filePath = "users.json"
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            email = request.form.get('email', '').strip()
            is_admin = bool(request.form.get('is_admin', False))

            # Validate username
            if not username.isalnum() or len(username) < 3:
                error_message = "Username must be at least 3 characters long and contain only letters and numbers."
                return render_template('userCreate.html', error_message=error_message)

            # Validate password
            if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password):
                error_message = "Password must be at least 8 characters long, contain both letters and numbers."
                return render_template('userCreate.html', error_message=error_message)

            # Validate email
            if "@" not in email or "." not in email.split("@")[-1]:
                error_message = "Invalid email format. Please enter a valid email address."
                return render_template('userCreate.html', error_message=error_message)
            
            try:
                with open(filePath, "r") as file:
                    users = json.load(file)
            except (FileNotFoundError, json.decoder.JSONDecodeError):
                users = [{"Username": 'roger', "Password" : 'roger123'}]  #empty list if file not found or invalid

            
            if any(user['Username'] == username for user in users):
                error_message = "There is already a user with that name. Please enter another."
            elif any(user['Email'] == email for user in users):
                error_message = "This email is already linked with another account. Try a different one."
            else:
                
                add_new_user(users, username, password, email, is_admin, filePath)
                flash("User created successfully!")
                return redirect('/viewUsers')  #Redirect to view users page

        return render_template('userCreate.html', error_message=error_message)


    @app.route("/viewUsers")    
    def view_users():
        try:
            with open("users.json", "r") as file:
                users = json.load(file)
            return render_template("viewUsers.html", users=users)
        except FileNotFoundError:
            return render_template("viewUsers.html", users=[])

    @app.route("/deleteUser", methods=['GET', 'POST'])
    def delete_user():
        if request.method == 'POST':
            username = request.form.get('username', '')
            filePath = "users.json"
            try:
                with open(filePath, "r") as file:
                    users = json.load(file)
            except (FileNotFoundError, json.decoder.JSONDecodeError):
                users = []

            # Filter out the user to be deleted
            users = [user for user in users if user['Username'] != username]

            # Save the updated list back to the file
            with open(filePath, "w") as file:
                json.dump(users, file, indent=4)

            flash("User deleted successfully!")
        return render_template('viewUser.html')

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
