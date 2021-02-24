from flask import Flask, render_template, redirect, url_for, flash, g, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey, exc, Text
from sqlalchemy.orm import relationship

from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.wrappers import CommonRequestDescriptorsMixin
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps







app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

#Login manager
login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user):
    return User.query.get(int(user))


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    name = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("CommentPost", back_populates="comment_author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")          
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

 
class CommentPost(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.String(250), nullable=False)
    text = db.Column(db.Text, nullable=False)
    #*******Add child relationship*******#
    #"users.id" The users refers to the tablename of the Users class.
    #"comments" refers to the comments property in the User class.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))    
    comment_author = relationship("User", back_populates="comments")  
    
    
db.create_all()

## APP.ROUTE 

def is_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs): 
        try:       
            if current_user.id == 1:
                return f(*args, **kwargs)
            else:
                return abort(403)
        except AttributeError:
            current_user.id = 0
            return abort(403)
    return decorated_function

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all() 
    print(current_user, current_user.is_authenticated)
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            password_hash = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            user = User(email=form.email.data, name=form.name.data, password=password_hash)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            #admin = is_admin()            
            return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))
        except exc.IntegrityError:
            flash('This user already exists')
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)

@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash("This username doesn't not exists, please register or try another username")
        else:
            check_password = check_password_hash(user.password, form.password.data)
            if not check_password:
                flash("Incorrect password for this username")
            else:
                login_user(user)
                #admin=is_admin()
                return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))                     
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)

@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)       
    form  = CommentForm()
    if request.method == 'POST':
        if current_user.is_authenticated:
            data = request.form.get('ckeditor')
            comment = CommentPost(author_id=current_user.name, post_id=post_id, text=data[3:-4])
            db.session.add(comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated)   
        else:
            flash('Login requiered to comment')
            return redirect(url_for('login'))
    comments = CommentPost.query.filter(CommentPost.post_id==post_id)        
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, comments=comments, form=form)

@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['POST', 'GET'])
@is_admin
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(            
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts", logged_in=current_user.is_authenticated))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@is_admin
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, logged_in=current_user.is_authenticated))
    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@is_admin
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated ))


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))

if __name__ == "__main__":
    app.run(debug=True)
