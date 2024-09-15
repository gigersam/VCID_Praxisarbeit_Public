"""
This script runs the application using a development server.
It contains the definition of routes and views for the application.7
http://localhost/env/
"""


from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Flask Initialisierug
app = Flask(__name__)
# MySQL Connection String
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://USERNAME:PASSWORD@IP:3306/DBNAME'
# Secret Key for App
app.config['SECRET_KEY'] = 'SECRETKEY' 

# SQLAlchemy Initialisierung for DB
db = SQLAlchemy()
db.init_app(app)

# Database Models:
# Database Model for the User-Auth
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(512))
    email = db.Column(db.String(128))
    editor = db.Column(db.Boolean, default=False, nullable=False)
    # Function to set new Enc Password
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    # Function to check Enc Password
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Database Model for Companies of the affected Products in CVE
class Company(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    companyname = db.Column(db.String(80), unique=True, nullable=False)
    website = db.Column(db.String(128))

# Database Model for the Products used in CVE
class Products(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product = db.Column(db.String(80), unique=True, nullable=False)
    companyfk = db.Column(db.Integer, db.ForeignKey('company.id'))

# Database Model for the Registered CVE's
class CVE(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cveid = db.Column(db.String(80), unique=True, nullable=False)
    cvescore = db.Column(db.String(4))
    vector = db.Column(db.String(256))
    source = db.Column(db.String(128))
    linktosource = db.Column(db.String(1024))
    cvedescipion = db.Column(db.String(2048))
    productsfk = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    userfk = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    solved = db.Column(db.Boolean, default=False, nullable=False)
    solvedby = db.Column(db.Integer, db.ForeignKey('user.id'))
    # Function to serialize the Database items for return in API (/api/cve)
    def serialize(self):
        return {
            'id': self.id,
            'cveid': self.cveid,
            'cvescore': self.cvescore,
            'source': self.source,
            'linktosource': self.linktosource,
            'solved': self.solved
        }

# Migrate Object of DB-Model in App
migrate = Migrate(app, db)

# Make the WSGI interface available at the top level so wfastcgi can get it.
wsgi_app = app.wsgi_app

# Login Manager instantiate for Auth handling
login_manager = LoginManager()
login_manager.init_app(app)
# If not Authenticated return Page login
login_manager.login_view = 'login'

# Loading Users from Database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Default Route and Route CVE only GET. CVE uses the template cve.html. cve.html Requieres Objects from Database (CVE,Products,User)
@app.route('/', methods=['GET'])
@app.route('/cve', methods=['GET'])
def cve():
    cves = CVE.query.all()
    products = Products.query.all()
    users = User.query.all()
    return render_template('cve.html', cves=cves, products=products, users=users)

# Route CVE only POST. CVE uses the template cve.html. cve.html Requieres Objects from Database (CVE,Products,User). Change Value solved with user who marked it as solved.
# Splited because for changes a login is required.
@app.route('/cve', methods=['POST'])
@login_required
def cvepost():
    tochangestate = request.form['changevalue']
    tochangecve = CVE.query.get(tochangestate)
    # Check current State of feld solved. If True set to False, if else set to True and add User ID who changed it.
    if tochangecve.solved == True:
        newstate = False
        solvedbyuser = None
    else:
        newstate = True
        solvedbyuser = current_user.id
    
    # Write to change Database
    tochangecve.solved = newstate
    tochangecve.solvedby = solvedbyuser
    db.session.commit()
    
    # Rerender Page
    cves = CVE.query.all()
    products = Products.query.all()
    users = User.query.all()
    return render_template('cve.html', cves=cves, products=products, users=users)

# Route for Login. 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Get Userdata form Database
        user = User.query.filter_by(username=username).first()
        # Validate username and password, else return error
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('cve')) 
        else:
            flash('Invalid username or password')
            return render_template('login.html')
    # if no match return template login.html
    return render_template('login.html')

#Route for Logout. To Access Logout a login is required. After successful logout return to Login.
@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Route for register new users. Accepts GET and POST. No Login required. After successful registration returns to Login.
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Check Method: POST else GET
    if request.method == 'POST':
        # Get Form Felds
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        editor = "on"

        # Get Username and Email for check if exist
        user = User.query.filter_by(username=username).first()
        email_check = User.query.filter_by(email=email).first()
        # Check if Username already exist
        if user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        # Check if Email already exist
        if email_check:
            flash('Email already registered. Please use a different email.', 'danger')
            return redirect(url_for('register'))
        # Check if Password matches
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))
        # Check Editor Feld to set as Boolean
        if editor == "on":
            editor = True
        else:
            editor = False

        # Generate Password-Hash (default hashing method gets used "pbkdf2:sha256")
        hashed_password = generate_password_hash(password) 
        # Create User-Object and add to Database and return to Login
        new_user = User(username=username, email=email, password_hash=hashed_password, editor=editor)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Route for adding CVE's. Accepts GET and POST. Requires Authentication. Renders cveadd.html. cveadd.html requires Products Data 
@app.route('/cve/add', methods=['GET', 'POST'])
@login_required
def cveadd():
    # Check Method: POST else GET
    if request.method == 'POST':
        # Get Form Felds
        cveid = request.form['cveid']
        cvescore = request.form['cvescore']
        vector = request.form['vector']
        source = request.form['source']
        linktosource = request.form['linktosource']
        cvedescipion = request.form['cvedescription']
        productsfk = request.form['productsfk']
        userfk = current_user
        
        # Check cveid for Empty String Data
        if cveid == "":
           flash('CVE-ID must contain a value', 'danger')
           products = Products.query.all()    
           return render_template('cveadd.html', products=products)
        
        # Check cveid for Empty Data
        cveidcheck = CVE.query.filter_by(cveid=cveid).first()
        if cveidcheck:
           flash('CVE-ID already registered', 'danger')
           products = Products.query.all()    
           return render_template('cveadd.html', products=products)
        
        # Create new CVE object and Add to Database. Return CVE View
        new_cve = CVE(cveid=cveid, cvescore=cvescore, vector=vector, source=source, linktosource=linktosource, cvedescipion=cvedescipion, productsfk=productsfk, userfk=userfk.id, solved=0)
        db.session.add(new_cve)
        db.session.commit()
        
        return redirect(url_for('cve')) 
    # if no match return template cveadd.html with products data
    products = Products.query.all()    
    return render_template('cveadd.html', products=products)

# Route for adding, viewing and deleting Products. Accepts GET and POST. Requires Authentication. Renders product.html. product.html requires Products and Company Data 
@app.route('/product', methods=['GET', 'POST'])
@login_required
def products():
    # Check Method: POST else GET
    if request.method == 'POST':
        # Check if Button with the value Add got used. 
        if request.form['btn'] == 'Add':
            # Get Form Felds
            product = request.form['product']
            companyfk = request.form["companyfk"]
            
            # Check cveid for Empty String Data and create error
            if product == "":
                flash('Product must contain a value', 'danger') 
                products = Products.query.all()    
                company = Company.query.all()
                return render_template('product.html', products=products, company=company)
            # Check companyfk for Choose... String Data and create error. Return product.html with Products and Company Data
            if companyfk == 'Choose...':
                flash('Company must be selected', 'danger') 
                products = Products.query.all()    
                company = Company.query.all()
                return render_template('product.html', products=products, company=company)
            # Get Product and Check if already exists and create error. Return product.html with Products and Company Data
            productcheck = Products.query.filter_by(product=product).first()
            if productcheck:
                flash('Product already registered', 'danger')
                products = Products.query.all()    
                company = Company.query.all()
                return render_template('product.html', products=products, company=company)
            # Create new Products object and Add to Database. Return product.html with Products and Company Data
            new_product = Products(product=product, companyfk=companyfk)
            db.session.add(new_product)
            db.session.commit()
            products = Products.query.all()
            company = Company.query.all()
            return render_template('product.html', products=products, company=company)
        
        else:
            # Get used Button Value. ID of Product expected. Get Data from Products.
            productid = request.form['btn']
            product = Products.query.get(productid)
            company = Company.query.all()
            # Check if Product ID gets used in CVE as FK
            incve = CVE.query.filter_by(productsfk=product.id).first()
            # If in Prodcut ID gets used in CVE rise error. Return product.html with Products and Company Data
            if incve:
                flash("Company used in CVE.")
                company = Company.query.all()
                products = Products.query.all()
                return render_template('product.html', products=products, company=company)
            # Else Remove Product from Table Products in Database and Return product.html with Products and Company Data
            else:
                db.session.delete(product)
                db.session.commit()
                company = Company.query.all()
                products = Products.query.all()
                return render_template('product.html', products=products, company=company)
    # Default Action Return product.html with Products and Company Data  
    products = Products.query.all()
    company = Company.query.all()
    return render_template('product.html', products=products, company=company)

# Route for adding, viewing and deleting Products. Accepts GET and POST. Requires Authentication. Renders company.html. company.html requires Company Data 
@app.route('/company', methods=['GET', 'POST'])
@login_required
def company():
    # Check Method: POST else GET
    if request.method == 'POST':
        # Check if Button with the value Add got used. 
        if request.form['btn'] == 'Add':
            # Get Form Felds
            companyname = request.form['companyname']
            website = request.form['website']
            # Check companyname for Empty String Data and create error Return company.html with Company Data
            if companyname == "":
                flash('Companyname must contain a value', 'danger') 
                company = Company.query.all()
                return render_template('company.html', company=company)
            # Get companyname and Check if already exists and create error. Return company.html with Company Data
            companynamecheck = Company.query.filter_by(companyname=companyname).first()
            if companynamecheck:
                flash('Company already registered', 'danger') 
                company = Company.query.all()
                return render_template('company.html', company=company)
            # Create new Company object and Add to Database. Return company.html with Company Data
            new_product = Company(companyname=companyname, website=website)
            db.session.add(new_product)
            db.session.commit()
            company = Company.query.all()
            return render_template('company.html', company=company)
        
        else:
            # Get used Button Value. ID of Company expected. Get Data from Company.
            companyid = request.form['btn']
            company = Company.query.get(companyid)
            # Check if Company ID gets used in Products as FK
            inproduct = Products.query.filter_by(companyfk=company.id).first()
            # If in Company ID gets used in Products rise error. Return company.html with Company Data
            if inproduct:
                flash("Company used in Products.")
                company = Company.query.all()
                return render_template('company.html', company=company)
             # Else Remove Comapny from Table Products in Database and Return company.html with Company Data
            else:
                db.session.delete(company)
                db.session.commit()
                company = Company.query.all()
                return render_template('company.html', company=company)
    # Default Action Return company.html with Company Data    
    company = Company.query.all()
    return render_template('company.html', company=company)

# Route for getting CVE in a JSON Format (RestAPI). Not Authentification Required
@app.route('/api/cve', methods=['GET'])
def apicve():
    # Get All CVE from Database
    cves = CVE.query.all()
    # serialize Data recived from CVE with the Function "serialize" in the Model CVE
    serialized_cves = [cve.serialize() for cve in cves]
    # Return Data as JSON
    return jsonify(serialized_cves)


# Start App on Run 
if __name__ == '__main__':
    import os
    # Check for listening on (IP/Hostname)
    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        # Check Port-Binding on 5555 or defined Port
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        # If Port set Fails, set to 5555
        PORT = 5555
    # Start Server on Host and Port
    app.run(HOST, PORT)

