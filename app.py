from flask import Flask, render_template, flash, redirect, abort, url_for, session, request, logging, jsonify, send_from_directory
#from data import Articles
from flask_mysqldb import MySQL
from flask_wtf import RecaptchaField
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
from werkzeug.utils import secure_filename
import os
from password_strength import PasswordPolicy

app = Flask(__name__)

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}
API_KEY = "KTXvLBD7TvoBjVxp9iRyJcJLgWeM3mkS"

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'usuarios_puser19'
app.config['MYSQL_PASSWORD'] = 'TalooUser_2019.'
app.config['MYSQL_DB'] = 'usuarios_puser'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SECRET_KEY'] = '05686F1CD04C96751262607325F7BA48B3561E566D95ACD2B4E0F5045F5D8DD1'

app.config['RECAPTCHA_USE_SSL']= False
app.config['RECAPTCHA_PUBLIC_KEY']='6LeFLrwUAAAAAHkPL4QeGZGHHFYiMm78MhO0Fe3C'
app.config['RECAPTCHA_PRIVATE_KEY']='6LeFLrwUAAAAANL76lW5MN7fqWD_xsT29TOCChZU'
app.config['RECAPTCHA_OPTIONS']= {'theme':'black'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


# init MYSQL
mysql = MySQL(app)
#Articles = Articles()

@app.errorhandler(404)
def page_not_found(e):
    return render_template('dashboard.html'), 404
    
# Index
@app.route('/')
def index():
    return render_template('home.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')


# Articles
@app.route('/articles')
def articles():
    # Create cursor
    cur = mysql.connection.cursor()

    # Get articles
    result = cur.execute("SELECT * FROM articles")

    articles = cur.fetchall()

    if result > 0:
        return render_template('articles.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('articles.html', msg=msg)
    # Close connection
    cur.close()


#Single Article
@app.route('/article/<string:id>/')
def article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get article
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

    article = cur.fetchone()

    return render_template('article.html', article=article)


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')
    recaptcha = RecaptchaField()


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        policy = PasswordPolicy.from_names(
            length=8,  # min length: 8
            uppercase=1,  # need min. 2 uppercase letters
            numbers=2,  # need min. 2 digits
            special=0,  # need min. 2 special characters
            nonletters=0,  # need min. 2 non-letter characters (digits, specials, anything)
        )

        validate_password = policy.test(form.password.data)

        # Create cursor
        cur = mysql.connection.cursor()

        user_validator = cur.execute("SELECT username FROM users WHERE username = %s", [username])

        if user_validator == 0 and len(validate_password) == 0:
            # Execute query
            cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

            # Commit to DB
            mysql.connection.commit()

            # Close connection
            cur.close()

            flash('¡Ahora que estás registrado puedes ingresar!', 'success')

            return redirect(url_for('login'))
        else:
            if len(validate_password) != 0:
                error_password = "¡Contraseña muy débil, incluya una Mayúscula y al menos 2 números!"
            else:
                error_user = "None"
            if user_validator != 0:
                error_user = "¡Usuario o contraseña erronea!"
            else:
                error_password = "None"
            return render_template('register.html', form=form, error_user=error_user, error_password=error_password)
            # Close connection
            cur.close()
    return render_template('register.html', form=form)

class LoginForm(Form):
    
    username = StringField('Usuario', [validators.Length(min=3, max=25)])
    password = PasswordField('Password', [validators.DataRequired()])
    recaptcha = RecaptchaField()

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm(request.form)

    if request.method == 'POST' and form.validate():

        # Get Form Fields
        username = form.username.data
        password_candidate = form.password.data
        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                #flash('¡Bienvenido! Ahora podrás publicar todas tus ofertas 😁', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = '* ¡Usuario/Contraseña errone@, por favor intente denuevo!'
                return render_template('login.html', error=error, form=form)
            # Close connection
            cur.close()
        else:
            error = '¡Contraseña erronea, por favor intente denuevo!'
            return render_template('login.html', error=error, form=form)

    return render_template('login.html', form=form)

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            #flash('No autorizado, por favor inicie a su perfil', 'danger')
            return redirect(url_for('login'))
    return wrap

##################################################
################## Starts API's ##################
##################################################

@app.route("/api/1.0/uploads")
def list_files():
    """Endpoint to list files on the server."""
    headers = request.headers
    auth = headers.get("X-Api-Key")
    if auth == API_KEY:
        files = []
        for filename in os.listdir(UPLOAD_FOLDER):
            path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(path):
                files.append(filename)
        return jsonify(files)
    else:
        return jsonify({"message": "ERROR: Unauthorized"}), 401


@app.route("/api/1.0/files/<path:path>")
def get_file(path):
    """Download a file."""
    headers = request.headers
    auth = headers.get("X-Api-Key")
    if auth == API_KEY:
        return send_from_directory(UPLOAD_FOLDER, path, as_attachment=True)
    else:
        return jsonify({"message": "ERROR: Unauthorized"}), 401


@app.route("/api/1.0/files/<filename>", methods=["POST"])
def post_file(filename):
    """Upload a file."""
    headers = request.headers
    auth = headers.get("X-Api-Key")
    if auth == API_KEY:
        if "/" in filename:
            # Return 400 BAD REQUEST
            abort(400, "no subdirectories directories allowed")

        with open(os.path.join(UPLOAD_FOLDER, filename), "wb") as fp:
            fp.write(request.data)

        # Return 201 CREATED
        return "", 201
    else:
        return jsonify({"message": "ERROR: Unauthorized"}), 401

@app.route("/api/1.0/db_us")
def list_files_db():
    headers = request.headers
    auth = headers.get("X-Api-Key")

    if auth == API_KEY:
        # Create cursor
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM archivos)
        rows = cur.fetchall()
		resp = jsonify(rows)
		resp.status_code = 200
		return resp
    else:
        return jsonify({"message": "ERROR: Unauthorized"}), 401
####################################################

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    #flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@is_logged_in
def dashboard():

    if request.method == 'POST':

        # check if the post request has the file part
        if 'file' not in request.files:
            flash('¡Error subiendo, intente denuevo!')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No se seleccionó ningún archivo 😞')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], session['username'] + filename))
            # Create Cursor
            cur = mysql.connection.cursor()

            # Execute
            cur.execute("INSERT INTO archivos(nombre_usuario, archivo) VALUES(%s, %s)",(session['username'], filename))

            # Commit to DB
            mysql.connection.commit()

            #Close connection
            cur.close()
            flash('Archivo subido de manera exitosa 😊')
            return redirect('/dashboard')
        else:
            flash('Solo puedes subir archivos pdf, doc y docx 🙁')
            return redirect(request.url)
    return render_template('dashboard.html')

@app.route('/uploads/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# Article Form Class
class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])

# Add Article
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)",(title, body, session['username']))

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Article Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)

# Upload files CV
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload_cv', methods=['GET', 'POST'])
@is_logged_in
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected for uploading')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File successfully uploaded')
            return redirect('/upload_cv')
        else:
            flash('Allowed file types are txt, pdf, png, jpg, jpeg, gif')
            return redirect(request.url)
    return render_template('upload.html')

# Edit Article
@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get article by id
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

    article = cur.fetchone()
    cur.close()
    # Get form
    form = ArticleForm(request.form)

    # Populate article form fields
    form.title.data = article['title']
    form.body.data = article['body']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']

        # Create Cursor
        cur = mysql.connection.cursor()
        app.logger.info(title)
        # Execute
        cur.execute ("UPDATE articles SET title=%s, body=%s WHERE id=%s",(title, body, id))
        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Article Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form=form)

# Delete Article
@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM articles WHERE id = %s", [id])

    # Commit to DB
    mysql.connection.commit()

    #Close connection
    cur.close()

    flash('Article Deleted', 'success')

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)
