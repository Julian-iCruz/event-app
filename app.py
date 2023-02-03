from flask import Flask, render_template, redirect, url_for, request, flash
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from config import DATABASE_CONNECTION_URI

app = Flask(__name__)

app.config['SECRET_KEY'] = 'PxtxjtCaxqmLeSmVNWoMwUcEiPkTHZ'
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_CONNECTION_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(256))
    events_id =  db.relationship('Event', backref='users' ,lazy=True)

class Event(db.Model):
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(20), nullable=False)
    place = db.Column(db.String(100))
    address = db.Column(db.String(100))
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    modality = db.Column(db.String(15), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __init__(self, name, category, place, address, start_date, end_date, modality, user_id):
        self.name = name
        self.category = category
        self.place = place
        self.address = address
        self.start_date = start_date
        self.end_date = end_date
        self.modality = modality
        self.user_id = user_id

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=30)])
    #remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=4, max=30)])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    form_state = {
        'form':form,
        'status':current_user.is_authenticated
        }

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('events'))
        flash('Invalid username or password')
        return render_template('login.html', form=form_state)
    return render_template('login.html', form=form_state)

@app.route('/signup', methods=['GET','POST'])
def signup():
    form = RegisterForm()
    formulario = {'form':form}
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully')
        return render_template('login.html', form=formulario)
    return render_template('signup.html', form=formulario)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/events')
@login_required
def events():
    events = list(Event.query.filter(Event.user_id == current_user.id))
    list_events = []
    for e in events:
        list_events.append([e.name, e.category, e.place, e.address, e.start_date, e.end_date, e.modality, e.id])
    show_vars = {
        'username':current_user.username,
        'status':current_user.is_authenticated,
        'events': list_events,
        'drop_category':['Conferencia', 'Seminario', 'Congreso', 'Curso'],
        'drop_modality':['Presencial', 'Virtual']
        }
    
    return render_template('events.html', form=show_vars)

@app.route("/events/create", methods=['POST'])
@login_required
def create():
    name = request.form['name']
    category = request.form['category']
    place = request.form['place']
    address = request.form['address']
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    modality = request.form['modality']  

    new_event = Event(name, category, place, address, start_date, end_date, modality, current_user.id)
    db.session.add(new_event)
    db.session.commit()
    return redirect(url_for('events'))

@app.route("/events/delete/<id>", methods=['GET'])
@login_required
def delete(id):
    db.session.delete(Event.query.get(id))
    db.session.commit()
    flash('Event deleted successfully!')
    return redirect(url_for('events'))

@app.route("/events/update/<id>", methods=['GET', 'POST'])
@login_required
def update(id):
    event = Event.query.get(id)
    event_state = {
        'username':current_user.username,
        'event':event,
        'status':current_user.is_authenticated
        }
    if request.method == "POST":
        event.name = request.form['name']
        event.category = request.form['category']
        event.place = request.form['place']
        event.address = request.form['address']
        event.start_date = request.form['start_date']
        event.end_date = request.form['end_date']
        event.modality = request.form['modality']

        db.session.commit()
        flash('Event updated successfully!')
        return redirect(url_for('events'))
    return render_template('update.html', form=event_state)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)