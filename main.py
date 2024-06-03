from flask import Flask, render_template, request, flash, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_bcrypt import Bcrypt
import json

app=Flask(__name__)
app.config["SECRET_KEY"] = '45b2eca2500d518956907149'
app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///ums.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config["SESSION_PERMANENT"]=False
app.config["SESSION_TYPE"]='filesystem'
db=SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)

# User Class
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(255), nullable=False)
    ghid = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    classes = db.Column(db.String(255))  
    kasm_server_needed = db.Column(db.Boolean, default=False)
    password = db.Column(db.String(255), nullable=False)
    status = db.Column(db.Integer,default=1, nullable=False)

    def __repr__(self):
        return f'User("{self.id}","{self.fname}","{self.ghid}","{self.email}","{self.classes}","{self.kasm_server_needed}","{self.status}")'




# main index 
@app.route('/') 
def index():
    return render_template('/index.html', 
    title="")

# admin login
@app.route('/admin/') 
def adminIndex():
    return render_template('admin/index.html', 
    title="Admin Login")

# -------------- user area ----------------

# user login
@app.route('/user/', methods=["POST", "GET"]) 
def userIndex():
    if session.get("user_id"):
        return redirect("/user/dashboard")
    if request.method == "POST":
       
        #get name of the field 
        email = request.form.get('email')
        password = request.form.get('pwd')

        # checking if user exists 
        users = User().query.filter_by(email=email).first()
        if users and bcrypt.check_password_hash(users.password, password):
             # check the admin approval
            is_approve = User.query.filter_by(id=users.id).first()
           # first return the is_approve:
           # return f'{is_approve.status}'
            if is_approve.status == 0:
                flash('Your account is not approved by admin.', 'danger')
                return redirect('/user/')
            else:    
                session['user_id'] = users.id
                session['name'] = users.fname
                flash('Login Successful', 'success')
                return redirect('/user/dashboard')
        else: 
            flash('Incorrect email and/or password', 'danger')
            return redirect('/user/')
    else:
        return render_template('user/index.html', 
        title="User Login")

# user resigter
@app.route('/user/signup', methods=["POST", "GET"]) 
def userSignup():
    if session.get("user_id"):
        return redirect("/user/dashboard")
    if request.method == 'POST':
        # get all input fields
        fname = request.form.get('fname')
        ghid = request.form.get('ghid')
        email = request.form.get('email')
        classes = request.form.getlist('classes')
        kasm_server_needed = True if 'kasm_server_needed' in request.form else False
        password = request.form.get('pwd')

        # check all fields for null
        if fname == "" or ghid == "" or email == "" or password == "" : 
             flash('Please fill all the fields', 'danger')
             return redirect('/user/signup')
        else:
            is_email = User().query.filter_by(email=email).first()
            if is_email: 
                flash('Email already in use by existing account', 'danger')
                return redirect('/user/signup')
            else:
                try:
                    hash_password = bcrypt.generate_password_hash(password, 10)
                    classes_str = ','.join(classes)
                    user = User(fname=fname, ghid=ghid, email=email, classes=classes_str, kasm_server_needed=kasm_server_needed, password=hash_password)
                    db.session.add(user)
                    db.session.commit()
                    flash('Account created successfully, please wait for an admin to approve your account', 'success')
                    return redirect('/user/dashboard')
                except Exception as e:
                    print(f"Error during database operation: {e}")
                    db.session.rollback()
                    flash('An error occurred while creating the account', 'danger')
                    return redirect('/user/signup')

    else:
        return render_template('user/signup.html', 
        title="User Signup")


# user dashboard
@app.route("/user/dashboard")
def userDashboard():
    if session.get("user_id") == None:
        flash('Please log in first', 'danger')
        return redirect("/user/")
    
    if 'name' in session:
        user_name = session['name']
    else:
        flash('Please log in first', 'danger')
        return redirect('/user/')

    return render_template('user/dashboard.html', title="User Dashboard", name=user_name)

# user logout 
@app.route('/user/logout')
def userLogout():
    session.clear()
    return redirect("/user/")
    
# user change pwd 
@app.route('/user/change-password', methods=["POST", "GET"])
def userChangePassword():
    if session.get("user_id") == None:
        flash('Please log in first', 'danger')
        return redirect("/user/")
    if 'name' in session:
        user_name = session['name']
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('pwd')

        if email == "" or password == "":
            flash('Please complete all fields', 'danger')
            return redirect('/user/change-password')
        else: 
            users = User.query.filter_by(email=email).first()
        #    db.session.delete(users)
            db.session.commit()
            
            if users:
                hash_password = bcrypt.generate_password_hash(password, 10)
                User.query.filter_by(email=email).update(dict(password = hash_password))
                db.session.commit()
                flash('Password changed successfully', 'success')
                return redirect("/user/")
            else : 
                flash("Invalid email", 'danger')
                return redirect("/user/change-password")

    else:
        return render_template('user/change-password.html', title="Change Password", name=user_name)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)