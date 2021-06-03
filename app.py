from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length 
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
# from flask_security import Security, SQLAlchemyUserDatastore,UserMixin,RoleMixin


app = Flask(__name__,static_url_path='/static')
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to view this page."
# set optional bootswatch theme
app.config['FLASK_ADMIN_SWATCH'] = 'Lumen'
# https://bootswatch.com/3/



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(180))
    active = db.Column(db.Boolean(),default=True)
    role = db.Column(db.String(30),default='user')
    # confirmed_at = db.Column(db.DateTime())


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=40)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=40)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class MyModelView(ModelView):
    def is_accessible(self):
        
        # return current_user.is_authenticated
        # if the current_user role is admin, show the admin page
        # return current_user.role=='admin'
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.role=='admin'
        )

    # def inaccessible_callback(self, name, **kwargs):
    #     # redirect to login page if user doesn't have access
    #     return redirect(url_for('login'))
    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('login'))

admin = Admin(app, name='admin', template_mode='bootstrap3')
admin.add_view(MyModelView(User, db.session))


@app.route('/')
def index():
    return render_template('index.html')

# @app.route('/master')
# def master(self):
#     if self.is_accesible():
#             # return super().index()
#             return render_template('/admin/index.html')
#     else:
#         return self._handle_view()
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    msg=""
    if form.validate_on_submit(): 
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                if current_user.role=='admin':
                    return redirect(url_for('admin.index'))
                else:
                    return redirect(url_for('dashboard'))
                
        return render_template('login.html', form=form, msg='sorry, wrong username or password, please try it again')

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    msg=""
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        user_exist = User.query.filter_by(username=form.username.data).first()
        if user_exist:
            return render_template('signup.html', form=form, msg='username exists, please try another name')
        user_exist1 = User.query.filter_by(email=form.email.data).first()
        if user_exist1:
            return render_template('signup.html', form=form, msg='email exists, please try another email')
        
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        # return '<h1>New user has been created!</h1> '
        return redirect(url_for('login'))
        
    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
