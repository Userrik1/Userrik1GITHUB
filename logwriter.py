#!/usr/bin/env python3

import sys
import re
import configparser
import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, func, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from flask import Flask, request, jsonify, make_response
from functools import wraps
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import smtplib
from email.mime.text import MIMEText

# Настройка логирования
logging.basicConfig(filename='logwriter.log', level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

# Чтение конфигурации
config = configparser.ConfigParser()
config.read('config.ini', encoding='utf-8')

LOG_PATH = config['DEFAULT']['log_path']
LOG_FORMAT = config['DEFAULT']['log_format']
DB_TYPE = config['DEFAULT']['db_type']
DB_HOST = config['DEFAULT']['db_host']
DB_PORT = config['DEFAULT']['db_port']
DB_NAME = config['DEFAULT']['db_name']
DB_USER = config['DEFAULT']['db_user']
DB_PASSWORD = config['DEFAULT']['db_password']

EMAIL_ENABLED = config['DEFAULT'].getboolean('email_enabled', fallback=False)
EMAIL_HOST = config['DEFAULT'].get('email_host', '')
EMAIL_PORT = config['DEFAULT'].getint('email_port', 0)
EMAIL_USER = config['DEFAULT'].get('email_user', '')
EMAIL_PASSWORD = config['DEFAULT'].get('email_password', '')
EMAIL_TO = config['DEFAULT'].get('email_to', '')

# Настройка базы данных
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password = Column(String(50))
    role = Column(String(20))

class LogEntry(Base):
    __tablename__ = 'logs'
    id = Column(Integer, primary_key=True)
    ip = Column(String(45))
    datetime = Column(DateTime)
    request_method = Column(String(10))
    request_url = Column(Text)
    protocol = Column(String(10))
    status_code = Column(Integer)
    response_size = Column(Integer)
    referer = Column(Text)
    user_agent = Column(Text)

db_url = f"{DB_TYPE}+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
engine = create_engine(db_url, echo=False)
Session = sessionmaker(bind=engine)
session = Session()

# Настройка Flask API
app = Flask(__name__)

def parse_log_line(line):
    log_pattern = r'^(?P<ip>[\d\.]+) - - \[(?P<datetime>.+?)\] "(?P<request>.+?)" (?P<status>\d{3}) (?P<size>\d+|-) "(?P<referer>.*?)" "(?P<agent>.*?)"$'
    match = re.match(log_pattern, line)
    if match:
        groups = match.groupdict()
        request_parts = groups['request'].split()
        if len(request_parts) == 3:
            method, url, protocol = request_parts
        else:
            method, url, protocol = None, None, None
        log_entry = LogEntry(
            ip=groups['ip'],
            datetime=datetime.strptime(groups['datetime'], '%d/%b/%Y:%H:%M:%S %z'),
            request_method=method,
            request_url=url,
            protocol=protocol,
            status_code=int(groups['status']),
            response_size=int(groups['size']) if groups['size'].isdigit() else 0,
            referer=groups['referer'],
            user_agent=groups['agent']
        )
        return log_entry
    else:
        logging.error(f"Не удалось разобрать строку: {line}")
        return None

def parse_logs():
    try:
        with open(LOG_PATH, 'r', encoding='utf-8') as f:
            for line in f:
                log_entry = parse_log_line(line.strip())
                if log_entry:
                    session.add(log_entry)
        session.commit()
        logging.info("Логи успешно разобраны и сохранены в базу данных.")
        print("Логи успешно разобраны и сохранены в базу данных.")
    except Exception as e:
        logging.error(f"Ошибка при разборе логов: {e}")
        print(f"Ошибка при разборе логов: {e}")

def view_logs_by_date(start_date, end_date=None, ip=None):
    try:
        query = session.query(LogEntry)
        start_datetime = datetime.strptime(start_date, '%d.%m.%Y')
        query = query.filter(LogEntry.datetime >= start_datetime)
        if end_date:
            end_datetime = datetime.strptime(end_date, '%d.%m.%Y')
            query = query.filter(LogEntry.datetime <= end_datetime)
        if ip:
            query = query.filter(LogEntry.ip == ip)
        logs = query.all()
        for log in logs:
            print(f"{log.datetime} {log.ip} {log.request_method} {log.request_url} {log.status_code}")
    except Exception as e:
        logging.error(f"Ошибка при просмотре логов: {e}")
        print(f"Ошибка при просмотре логов: {e}")

def auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            return make_response('Требуется аутентификация.', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})
        user = session.query(User).filter_by(username=auth.username, password=auth.password).first()
        if not user:
            return make_response('Неверные учетные данные.', 401, {'WWW-Authenticate': 'Basic realm="Login required"'})
        request.user = user
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.user.role != 'admin':
            return make_response('Доступ запрещен.', 403)
        return f(*args, **kwargs)
    return decorated

@app.route('/api/logs', methods=['GET'])
@auth_required
def api_get_logs():
    try:
        ip = request.args.get('ip')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        group_by = request.args.get('group_by')
        query = session.query(LogEntry)
        if ip:
            query = query.filter(LogEntry.ip == ip)
        if start_date:
            start_datetime = datetime.strptime(start_date, '%d.%m.%Y')
            query = query.filter(LogEntry.datetime >= start_datetime)
        if end_date:
            end_datetime = datetime.strptime(end_date, '%d.%m.%Y')
            query = query.filter(LogEntry.datetime <= end_datetime)
        if group_by:
            if group_by == 'ip':
                query = query.with_entities(LogEntry.ip, func.count(LogEntry.id)).group_by(LogEntry.ip)
                result = [{'ip': ip, 'count': count} for ip, count in query.all()]
            elif group_by == 'date':
                query = query.with_entities(func.date(LogEntry.datetime), func.count(LogEntry.id)).group_by(func.date(LogEntry.datetime))
                result = [{'date': date.isoformat(), 'count': count} for date, count in query.all()]
            elif group_by == 'status_code':
                query = query.with_entities(LogEntry.status_code, func.count(LogEntry.id)).group_by(LogEntry.status_code)
                result = [{'status_code': status_code, 'count': count} for status_code, count in query.all()]
            else:
                return jsonify({'error': 'Неверный параметр group_by'}), 400
        else:
            logs = query.all()
            result = [{
                'ip': log.ip,
                'datetime': log.datetime.isoformat(),
                'request_method': log.request_method,
                'request_url': log.request_url,
                'status_code': log.status_code
            } for log in logs]
        return jsonify(result)
    except Exception as e:
        logging.error(f"Ошибка API: {e}")
        return jsonify({'error': 'Внутренняя ошибка сервера'}), 500

@app.route('/api/users', methods=['POST'])
@auth_required
@admin_required
def api_create_user():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']
        role = data['role']
        user = User(username=username, password=password, role=role)
        session.add(user)
        session.commit()
        return jsonify({'message': 'Пользователь создан успешно'}), 201
    except Exception as e:
        logging.error(f"Ошибка при создании пользователя: {e}")
        return jsonify({'error': 'Ошибка при создании пользователя'}), 500

def send_email(subject, message):
    if not EMAIL_ENABLED:
        return
    try:
        msg = MIMEText(message)
        msg['Subject'] = subject
        msg['From'] = EMAIL_USER
        msg['To'] = EMAIL_TO

        server = smtplib.SMTP(EMAIL_HOST, EMAIL_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASSWORD)
        server.sendmail(EMAIL_USER, [EMAIL_TO], msg.as_string())
        server.quit()
    except Exception as e:
        logging.error(f"Ошибка при отправке email: {e}")

class LogEventHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path == LOG_PATH:
            logging.info("Обнаружено изменение лог-файла")
            # Здесь можно добавить обработку новых строк в лог-файле
            # Или отправку уведомления при критической ошибке
            parse_logs()

def start_monitoring():
    event_handler = LogEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=LOG_PATH, recursive=False)
    observer.start()
    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

def create_user(username, password, role):
    try:
        user = User(username=username, password=password, role=role)
        session.add(user)
        session.commit()
        logging.info(f"Пользователь {username} создан успешно.")
        print(f"Пользователь {username} создан успешно.")
    except Exception as e:
        logging.error(f"Ошибка при создании пользователя: {e}")
        print(f"Ошибка при создании пользователя: {e}")

def main():
    if len(sys.argv) < 2:
        print("Использование:")
        print("  logwriter.py parse")
        print("  logwriter.py createuser <имя_пользователя> <пароль> <роль>")
        print("  logwriter.py monitor")
        print("  logwriter.py <дата> [ip]")
        print("  logwriter.py <дата_начала> <дата_конца>")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'parse':
        Base.metadata.create_all(engine)
        parse_logs()
    elif command == 'createuser':
        if len(sys.argv) != 5:
            print("Использование: logwriter.py createuser <имя_пользователя> <пароль> <роль>")
            sys.exit(1)
        username = sys.argv[2]
        password = sys.argv[3]
        role = sys.argv[4]
        create_user(username, password, role)
    elif command == 'monitor':
        threading.Thread(target=start_monitoring).start()
        app.run(host='0.0.0.0', port=5000)
    elif len(sys.argv) == 2:
        date = sys.argv[1]
        view_logs_by_date(date)
    elif len(sys.argv) == 3:
        if sys.argv[2].count('.') == 3:
            date = sys.argv[1]
            ip = sys.argv[2]
            view_logs_by_date(date, ip=ip)
        else:
            start_date = sys.argv[1]
            end_date = sys.argv[2]
            view_logs_by_date(start_date, end_date)
    else:
        print("Неверные аргументы.")
        sys.exit(1)

if __name__ == '__main__':
    main()
