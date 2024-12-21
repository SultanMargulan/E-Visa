from app import db
from app.models import User  # Замените User на ваши модели

def clear_database():
    db.session.query(User).delete()  # Удаляет все данные из таблицы User
    db.session.commit()
    print("Database cleared.")

if __name__ == '__main__':
    clear_database()
