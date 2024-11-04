from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from sqlalchemy import desc

from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3

from config import Config


app = Flask(__name__)

login = LoginManager(app)
login.login_view = 'login'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wall.db'
app.config['SECRET_KEY'] = Config.SECRET_KEY

db = SQLAlchemy(app)


class Post(db.Model):

    __tablename__ = 'posts'
    id = db.Column(db.Integer(), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text(), nullable=False)
    created_on = db.Column(db.DateTime(), default=datetime.utcnow)
    author = db.Column(db.String(63), nullable=False)

    def __repr__(self):
        return f'<{self.id}:{self.title[:10]}>'
    

class User(UserMixin, db.Model):

    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(63), index=True, unique=True)
    password_hash = db.Column(db.String(127))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def chech_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'{self.id}:{self.username[:10]}'


@login.user_loader
def load_user(id):
    return db.session.get(User, int(id))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/')
@app.route('/index')
def index():
    posts = Post.query.order_by(desc(Post.created_on)).all()

    return render_template('index.html', posts=posts)


@app.route('/reg', methods=['GET', 'POST'])
def reg():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password2 = request.form['password']

        if password != password2:
            flash('Пароли не совпадают')
            return render_template('reg.html')
        
        if len(username) > 63:
            flash('Длина имени пользователя не должна быть больше 63 символов')
            return render_template('reg.html')
        
        try:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
        except Exception as error:
            flash(f'Произошла ошибка: {error}')
            return render_template('reg.html')
        else:
            login_user(user)
            return redirect(url_for('index'))
        
    return render_template('reg.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        user = db.session.query(User).filter(User.username == request.form['username']).first()

        if user is not None:
            if not user.chech_password(request.form['password']):
                flash('Неверный пароль')
                return render_template('login.html')
            
            login_user(user)
            return redirect(url_for('index'))
        else:
            return redirect(url_for('reg'))
        
    return render_template('login.html')


@app.route('/profile/<username>')
def profile(username):
    user = db.session.query(User).filter(User.username == username).first()

    if user is None:
        return redirect(url_for('index'))
    
    posts = db.session.query(Post).filter(Post.author == username).order_by(desc(Post.created_on))

    return render_template('profile.html', username=username, posts=posts)


@login_required
@app.route('/new', methods=['GET', 'POST'])
def new_post():
    if not current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if 0 < len(title) < 256 and len(content) > 0:
            post = Post(title=title, content=content, author=current_user.username)

            try:
                db.session.add(post)
                db.session.commit()
            except Exception as error:
                flash(f'Возникла ошибка при записи в базу данных: {error}')
            else:
                return redirect(url_for('index'))
        
        else:
            flash('Ошибка, длина заголовка поста не соответствует стандартам. Максимальное количество символов заголовка - 255.')
            return render_template('newpost.html')
        
    return render_template('newpost.html')


if __name__ == '__main__':
    app.run(debug=True)