import google.generativeai as genai
from nltk.tokenize import sent_tokenize, word_tokenize
import re
from nltk import FreqDist
from nltk.corpus import stopwords
import nltk
from flask import Flask, render_template, request, redirect, url_for, flash,jsonify,session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


app = Flask(__name__)
app.secret_key = "your-secret-key-here"  # Change this for production


genai.configure(api_key='AIzaSyCOoAQyClkN6jGPl5iskpU0knbnERA-gVE')
model = genai.GenerativeModel('gemini-1.5-flash')


# Database setup
def init_db():
    conn = sqlite3.connect('users.db',check_same_thread=False)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL)''')
    conn.commit()
    conn.close()


init_db()


# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/log', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('users.db',check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect('/chats')
        else:
            flash('Invalid email or password', 'error')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect('/signup')
        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect('users.db',check_same_thread=False)
            c = conn.cursor()
            c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                      (username, email, hashed_password))
            conn.commit()
            conn.close()

            flash('Account created successfully! Please login.', 'success')
            return redirect('/log')
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
    return render_template('signup.html')


@app.route('/chats', methods=['GET'])
def index():
    # Initialize with empty questions
    return render_template('chat.html',
                           what_questions=[],
                           where_questions=[],
                           when_questions=[],
                           why_questions=[],
                           who_questions=[],username=session['username'])


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
    conn = sqlite3.connect('chat.db',check_same_thread=False)
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


def generate_socratic_response(user_input, conversation_history=None):
    if conversation_history is None:
        conversation_history = []

    is_seeking_answer = any(
        keyword in user_input.lower() for keyword in ["what is", "explain", "define", "how does", "why is"])

    if is_seeking_answer and len(conversation_history) > 1:
        prompt = f"""
        The user has been engaged in a Socratic dialogue and now seems to need a clear answer.
        Their latest input: "{user_input}"

        Conversation history: {conversation_history}

        Provide a **concise, structured answer** that:
        1. Directly addresses their doubt
        2. Summarizes key concepts
        3. Encourages further reflection with a follow-up question
        4. Avoids unnecessary complexity

        Format: 
        - **Answer**: [Clear explanation]
        - **Follow-up**: [One open-ended question]
        """
        response = model.generate_content(prompt)
        return {
            'response_type': 'answer',
            'content': response.text.strip()
        }
    else:
        prompt = f"""
        Act as a Socratic tutor. Your goal is to guide the user toward understanding through questions.
        User's statement: "{user_input}"
        Previous conversation: {conversation_history}
        Generate **one thoughtful question** that:
        1. Challenges assumptions or explores deeper implications
        2. Relates to the user's input
        3. Encourages critical thinking
        4. Avoids yes/no answers
        Return only the question.
        """
        response = model.generate_content(prompt)
        return {
            'response_type': 'question',
            'content': response.text.strip()
        }

@app.route('/socratic')
def soc():
    return render_template('socratic.html',username=session['username'])

@app.route('/socratic-tutor', methods=['POST'])
def socratic_tutor():
    if request.method == 'POST':
        try:
            data = request.get_json()
            user_message = data.get('message', '').strip()
            conversation_history = data.get('history', [])

            if not user_message:
                return jsonify({
                    'response_type': 'error',
                    'content': "Please provide a question or thought to discuss.",
                    'history': conversation_history
                }), 400

            response = generate_socratic_response(user_message, conversation_history)
            conversation_history.append({
                'user_message': user_message,
                'bot_response': response['content'],
                'response_type': response['response_type']
            })

            return jsonify({
                'response_type': response['response_type'],
                'content': response['content'],
                'history': conversation_history
            })

        except Exception as e:
            print(f"Error: {str(e)}")

            return jsonify({
                'response_type': 'error',
                'content': "I encountered an issue. Could you rephrase or elaborate?",
                'history': conversation_history if 'conversation_history' in locals() else []
            }), 500


@app.route('/logout')
def logs_out():
    session.clear()
    return redirect('/')

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value
    return value.strftime(format)


@app.route('/history')
def chat_history():
    if 'user_id' not in session:
        return redirect('/log')

    conn = sqlite3.connect('chat.db',check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM chat_history ORDER BY timestamp DESC')
    chat_history = cursor.fetchall()
    conn.close()

    return render_template('history.html',
                           chat_history=chat_history,
                           username=session['username'])

if __name__ == '__main__':
    app.run(debug=True)