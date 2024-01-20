from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, length, ValidationError
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://usuario:senha]@localhost/bancodedados'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'chave_secreta'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable = False, unique=True)
    password = db.Column(db.String(80), nullable = False)

with app.app_context():
    db.create_all()


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), length(min=4, max=20)], render_kw = {"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), length(min=4, max=20)], render_kw = {"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):

        existing_user_username = User.query.filter_by(
            username = username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), length(min=4, max=20)], render_kw = {"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), length(min=4, max=20)], render_kw = {"placeholder": "Password"})
    submit = SubmitField("Login")



@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    mensagem = ''
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                mensagem = 'Senha Incorreta'
        else:
            mensagem = 'Usuario não registrado!'

    return render_template('Login.html', form=form, mensagem=mensagem)


@app.route('/register', methods=["GET", "POST"])
def register():                        
    forms = RegisterForm()
    if forms.validate_on_submit():
        print('----------------', forms.username.data, forms.password.data)
        hashed_password = bcrypt.generate_password_hash(forms.password.data).decode('utf-8')
        novo_usuario = User(
        username = forms.username.data, password = hashed_password)
        db.session.add(novo_usuario)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', forms=forms)

@app.route('/dashboard', methods=["GET","POST"])
@login_required
def dashboard():

    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/sobremim')
def sobremim():
    return render_template('sobremim.html')


if __name__ == '__main__':
    app.run(debug=True)


