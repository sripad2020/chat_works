import google.generativeai as genai
from nltk.tokenize import sent_tokenize, word_tokenize
import re
from nltk import FreqDist
from nltk.corpus import stopwords
import nltk
from flask import Flask, render_template, request, redirect, url_for, flash,jsonify,session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key="the unique one"

nltk.download('punkt')
nltk.download('stopwords')

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    conn.commit()
    conn.close()


init_db()


@app.route('/')
def home():
    session.clear()
    return render_template('index.html')

@app.route('/login',methods=['GET','POST'])
def logs():
    return render_template('login.html')

@app.route('/log', methods=['POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['email']=email
            flash('Login successful!', 'success')
            return redirect('/chats')
        else:
            return redirect('/signups')

    return render_template('login.html')


@app.route('/signups')
def sign():
    return render_template('signup.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Basic validation
        if len(username) < 3:
            flash('Username must be at least 3 characters', 'error')
            return redirect(url_for('signup'))
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('signup'))
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
        existing_user = c.fetchone()

        if existing_user:
            conn.close()
            flash('Username or email already exists', 'error')
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                  (username, email, hashed_password))
        conn.commit()
        conn.close()

        flash('Account created successfully! Please log in.', 'success')
        return redirect('/login')

    return render_template('signup.html')


@app.route('/chats', methods=['GET'])
def index():
    # Initialize with empty questions
    return render_template('chat.html',
                           what_questions=[],
                           where_questions=[],
                           when_questions=[],
                           why_questions=[],
                           who_questions=[])


def convert_paragraph_to_points(paragraph, num_points=5):
    sentences = sent_tokenize(paragraph)
    words = word_tokenize(paragraph.lower())
    stop_words = set(stopwords.words('english'))
    filtered_words = [word for word in words if word.isalnum() and word not in stop_words]
    freq_dist = FreqDist(filtered_words)
    sentence_scores = {}
    for sentence in sentences:
        sentence_word_tokens = word_tokenize(sentence.lower())
        sentence_word_tokens = [word for word in sentence_word_tokens if word.isalnum()]
        score = sum(freq_dist.get(word, 0) for word in sentence_word_tokens)
        sentence_scores[sentence] = score
    sorted_sentences = sorted(sentence_scores, key=sentence_scores.get, reverse=True)
    return sorted_sentences[:num_points]


def clean_text(text):
    return re.sub(r'\*\*|\*', '', text)

def save_to_db(user_message, bot_response):
    conn = sqlite3.connect('chat.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_message TEXT NOT NULL,
            bot_response TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('INSERT INTO chat_history (user_message, bot_response) VALUES (?, ?)',
                   (user_message, bot_response))
    conn.commit()
    conn.close()
def generate_5w_questions(topic):
    genai.configure(api_key='AIzaSyCOoAQyClkN6jGPl5iskpU0knbnERA-gVE')
    model = genai.GenerativeModel('gemini-1.5-flash')

    prompt = f"""Generate 5 different types of questions about: {topic}
    Provide exactly 5 questions, one for each W:
    1. What question (explanation/definition)
    2. Where question (location/placement)
    3. When question (timing/duration)
    4. Why question (reason/purpose)
    5. Who question (people/roles)

    Format your response as:
    What|||What is...?
    Where|||Where can...?
    When|||When does...?
    Why|||Why is...?
    Who|||Who is...?"""

    response = model.generate_content(prompt)
    questions = {
        'what': [],
        'where': [],
        'when': [],
        'why': [],
        'who': []
    }

    if response.text:
        for line in response.text.split('\n'):
            if '|||' in line:
                w_type, question = line.split('|||')
                w_type = w_type.strip().lower()
                if w_type in questions:
                    questions[w_type].append(question.strip())

    return questions


@app.route('/chat', methods=['POST'])
def chatting():
    if request.method == 'POST':
        try:
            data = request.get_json()
            user_message = data.get('message', '')
            context = data.get('context', 'general')

            genai.configure(api_key='AIzaSyCOoAQyClkN6jGPl5iskpU0knbnERA-gVE')
            model = genai.GenerativeModel('gemini-1.5-flash')

            # Generate main response
            prompt = f"Provide a detailed response to: {user_message}"
            response = model.generate_content(prompt)
            generated_text = clean_text(response.text)

            save_to_db(user_message, generated_text)

            # Generate 5W questions
            questions = generate_5w_questions(user_message)

            return jsonify({
                'response': generated_text,
                'questions': {
                    'what': questions['what'],
                    'where': questions['where'],
                    'when': questions['when'],
                    'why': questions['why'],
                    'who': questions['who']
                }
            })
        except Exception as e:
            print(f"Error: {str(e)}")
            return jsonify({
                'response': "Sorry, I encountered an error processing your request.",
                'questions': {
                    'what': [],
                    'where': [],
                    'when': [],
                    'why': [],
                    'who': []
                }
            }), 500

@app.route('/logout')
def logs_out():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)