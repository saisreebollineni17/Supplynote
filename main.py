from flask import Flask, redirect, render_template, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import string
import random
from datetime import datetime, timedelta
from urllib.parse import urlparse
from werkzeug.user_agent import UserAgent
from sqlalchemy.orm import deferred
from user_agents import parse

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:root@localhost/url_31244"
app.config['SECRET_KEY'] = "secret_key_31244"
db = SQLAlchemy(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_db():
    with app.app_context():
        db.create_all()

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_url = db.Column(db.String(10000), nullable=False)
    username = db.Column(db.String(20), nullable=False)
    short_url = db.Column(db.String(10), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    clicks = db.Column(db.Integer, default=0)
    last_click_at = db.Column(db.DateTime, nullable=True)
    browsers = db.Column(db.String(200), nullable=True)

    def is_valid(self):
        expiration_time = self.created_at + timedelta(hours=48)
        return datetime.utcnow() <= expiration_time

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(80), nullable=False)


class signUpForm(FlaskForm):

    first_name = StringField(validators=[InputRequired(), Length(min=1, max=50)], render_kw={"placeholder": "First Name"})

    last_name = StringField(validators=[InputRequired(), Length(min=1, max=50)], render_kw={"placeholder": "Last Name"})

    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    SignUp = SubmitField("Sign Up")

    def validate_username(self, username):
        existing_username = User.query.filter_by(
            username=username.data).first()
        
        if existing_username:
            raise ValidationError("Username already exists.")
        
class loginForm(FlaskForm):

    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    Login = SubmitField("Login")

@app.route("/")
def home():
    return render_template("base.html",title="URL Shortner", user=current_user)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect('/dashboard')
    else:
        form = loginForm()

        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect('/dashboard')


        return render_template("login.html",title="Login", form=form)

def generate_short_url():
    characters = string.ascii_letters + string.digits
    while True:
        short_url = ''.join(random.choice(characters) for i in range(6))
        existing_url = URL.query.filter_by(short_url=short_url).first()
        if not existing_url:
            return short_url
        
@app.route('/<short_url>')
def redirect_to_original(short_url):
    url = URL.query.filter_by(short_url=short_url).first()
    if url and url.is_valid():
        # Increment click count and update last click timestamp
        url.clicks += 1
        url.last_click_at = datetime.utcnow()

        # Get browser information using Flask-UserAgents
        user_agent_string = request.user_agent.string
        user_agent = parse(user_agent_string)

        # Extracted attributes
        browser = user_agent.browser.family
        version = user_agent.browser.version_string

        app.logger.debug(f"{browser} {version}")

        if url:
            app.logger.debug(f"Queried URL object: {url}")
            user_agent_string = request.user_agent.string
            user_agent = parse(user_agent_string)

            browser_info = f"{user_agent.browser.family}"
            
            if url.browsers == None:
                url.browsers = ""
                
            if browser_info not in url.browsers:
                # Append the new browser information
                app.logger.debug(f"Before updating browsers: {url.browsers}")
                url.browsers += f", {browser_info}"
                app.logger.debug(f"After updating browsers: {url.browsers}")
                db.session.commit()

        return redirect(url.original_url)
    else:
        flash(short_url+" cannot be shortened. Try again with a different URL.")
        return render_template('dashboard.html', user=current_user)

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    if request.method == "POST" and request.form.get("shorten_url"):
        original_url = request.form.get("original_url")

        if not original_url:
            flash("Please enter a valid URL.")
            return redirect(url_for("dashboard"))

            # Check if the scheme is present, if not, add it
        parsed_url = urlparse(original_url)
        if not parsed_url.scheme:
            original_url = "http://" + original_url

        existing_url = URL.query.filter_by(original_url=original_url).first()

        if existing_url:
            short_url = existing_url.short_url
            flash(f"Short URL already exists: {short_url}")
        else:
            short_url = generate_short_url()
            new_url = URL(original_url=original_url, short_url=short_url, username=current_user.username)
            db.session.add(new_url)
            db.session.commit()
            flash(f"Short URL created: {short_url}")

        return render_template("dashboard.html", title="Dashboard", user=current_user, short_url=short_url)
        
    if request.method=='POST' and request.form.get("view_analytics"):
        original_url = request.form.get('original_url')
        
        parsed_url = urlparse(original_url)
        if not parsed_url.scheme:
            original_url = "http://" + original_url

        url = URL.query.filter_by(original_url=original_url).first()

        if url:
            return render_template("dashboard.html", title="Dashboard", user=current_user, url=url)
        else:
            flash(f"No Analytics found for {original_url}")        

    return render_template("dashboard.html", title="Dashboard", user=current_user)

@app.route("/signup", methods=["GET", "POST"])
def signup_page():
    if current_user.is_authenticated:
        return redirect("/dashboard")
    else:
        form = signUpForm()
        if form.validate_on_submit():
            hash_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(first_name=form.first_name.data,
                            last_name=form.last_name.data,
                            username=form.username.data,
                            password=hash_password)
            
            db.session.add(new_user)
            temp = db.session.commit()
            print(temp)
            return redirect("/login")

        return render_template("signup.html",title="Sign Up", form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    create_db()
    app.run(debug = True)
    