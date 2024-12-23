from app import db, bcrypt, create_app
from app.models import User

# Create an application context
app = create_app()
with app.app_context():
    # Hash the password
    hashed_password = bcrypt.generate_password_hash("12345678").decode('utf-8')

    # Create the admin user
    admin_user = User(
        username='admin',
        email='yernurzhumanov.v1@gmail.com',
        password=hashed_password,
        is_admin=True
    )
    db.session.add(admin_user)
    db.session.commit()
    print("Admin user created successfully!")
