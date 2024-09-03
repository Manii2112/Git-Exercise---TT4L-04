from flask import Flask # type: ignore
from extensions import db, bcrypt, login_manager # type: ignore
from models import User # type: ignore
from portfolio.forms import ContactForm # type: ignore

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)

@app.route('/create_user')
def create_user():
    hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
    user = User(username='testuser', email='test@example.com', password=hashed_password)
    db.session.add(user)
    db.session.commit()
    return f"User {user.username} created!"

if __name__ == '__main__':
    print("Starting Flask app...")
    app.run(debug=True)


from flask import render_template, url_for, flash, redirect # type: ignore
from yourapp import app, db, bcrypt # type: ignore
from yourapp.forms import RegistrationForm, LoginForm # type: ignore
from yourapp.models import User # type: ignore
from flask_login import login_user, current_user, logout_user, login_required # type: ignore

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))
from flask_mail import Mail, Message # type: ignore

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@example.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'
mail = Mail(app)

@app.route("/contact", methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if form.validate_on_submit():
        msg = Message('Contact Form',
                      sender=form.email.data,
                      recipients=['admin@example.com'])
        msg.body = f'''
        Name: {form.name.data}
        Email: {form.email.data}
        Message: {form.message.data}
        '''
        mail.send(msg)
        flash('Your message has been sent!', 'success')
        return redirect(url_for('home'))
    return render_template('contact.html', title='Contact', form=form)