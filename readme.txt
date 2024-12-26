To properly clone and launch this project ensure you have GitHub, Python and PostgreSQL already downloaded in your system. Then, you need to run these commands in a terminal:
1. cd /path/to/the/project/folder - to navigate the terminal into the project folder
2. git clone https://github.com/SultanMargulan/E-Visa - to clone this repository to it
3. create a virtual environment and activate (replace <directory> with virtual environment name (e.g. venv)):
	for Windows: 
	python -m venv <directory>
	source <directory>/Scripts/activate
	for MacOS/Linux:
	python -m venv <directory>
	source <directory>/bin/activate
4. pip install -r requirements.txt - to install all dependencies
5. create a database for this project (you can do it in pgAdmin or directly in terminal)
6. create a file .env with the following configurations:
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY=<your_secret_key>
DATABASE_URL=postgresql://postgres:<password>@localhost/<your_bd_name>

MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=<your_gmail>
MAIL_PASSWORD=<your_app_password>
(in order to make email 2FA work, go into your gmail account and enable 2FA, then create an app password)
7. open up the admin_user.py file and change the email and password fields as needed. then, run the following command to create an admin user:
python admin_user.py
7. flask run - to run the server and the web application
8. you are all set!

(if you have problems with python commands, try typing python3 instead of python)

credits to Sultan Margulan, Yernur Zhumanov