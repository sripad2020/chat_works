import google.generativeai as genai
from nltk.tokenize import sent_tokenize, word_tokenize
import re
from nltk import FreqDist
from nltk.corpus import stopwords
import nltk
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "your-secret-key-here"  # Change this for production

# Configure Gemini AI
genai.configure(api_key='AIzaSyCOoAQyClkN6jGPl5iskpU0knbnERA-gVE')
model = genai.GenerativeModel('gemini-1.5-flash')


# Database initialization
def init_db():
    """Initialize both users and chat databases"""
    # Users database
    users_conn = sqlite3.connect('users.db', check_same_thread=False)
    users_c = users_conn.cursor()
    users_c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE NOT NULL,
                      email TEXT UNIQUE NOT NULL,
                      password TEXT NOT NULL)''')
    users_conn.commit()
    users_conn.close()

    # Chat database
    chat_conn = sqlite3.connect('chat.db', check_same_thread=False)
    chat_c = chat_conn.cursor()
    chat_c.execute('''CREATE TABLE IF NOT EXISTS chat_history
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     user_message TEXT NOT NULL,
                     bot_response TEXT NOT NULL,
                     conversation_type TEXT NOT NULL,
                     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                     user_id INTEGER)''')
    chat_conn.commit()
    chat_conn.close()


init_db()


# Helper functions
def clean_text(text):
    """Remove markdown formatting from text"""
    return re.sub(r'\*\*|\*', '', text)


def save_to_db(user_message, bot_response, conversation_type='regular'):
    """Save conversation to database"""
    conn = sqlite3.connect('chat.db', check_same_thread=False)
    cursor = conn.cursor()
    user_id = session.get('user_id', None)
    cursor.execute('''
        INSERT INTO chat_history 
        (user_message, bot_response, conversation_type, user_id) 
        VALUES (?, ?, ?, ?)
    ''', (user_message, bot_response, conversation_type, user_id))
    conn.commit()
    conn.close()


def generate_5w_questions(topic):
    """Generate What, Where, When, Why, Who questions about a topic"""
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


def generate_socratic_response(user_input, conversation_history=None):
    """Generate Socratic-style responses"""
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


# Routes
@app.route('/')
def home():
    """Home page route"""
    return render_template('index.html')


@app.route('/log', methods=['GET', 'POST'])
def login():
    """User login route"""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('users.db', check_same_thread=False)
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
    """User signup route"""
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
            conn = sqlite3.connect('users.db', check_same_thread=False)
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
    """Main chat interface"""
    if 'user_id' not in session:
        return redirect('/log')
    return render_template('chat.html',
                           what_questions=[],
                           where_questions=[],
                           when_questions=[],
                           why_questions=[],
                           who_questions=[],
                           username=session['username'])


@app.route('/chat', methods=['POST'])
def chatting():
    """Handle regular chat messages"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        user_message = data.get('message', '')
        context = data.get('context', 'general')

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


@app.route('/socratic')
def soc():
    """Socratic tutor interface"""
    if 'user_id' not in session:
        return redirect('/log')
    return render_template('socratic.html', username=session['username'])


@app.route('/socratic-tutor', methods=['POST'])
def socratic_tutor():
    """Handle Socratic tutor messages"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

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

        # Save to database
        save_to_db(user_message, response['content'], 'socratic')

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


@app.route('/history')
def chat_history():
    """Display chat history"""
    if 'user_id' not in session:
        return redirect('/log')

    user_id = session['user_id']
    selected_type = request.args.get('type', 'all')

    conn = sqlite3.connect('chat.db', check_same_thread=False)
    cursor = conn.cursor()

    # Get all conversation types
    cursor.execute('''
        SELECT DISTINCT conversation_type FROM chat_history 
        WHERE user_id = ? 
        ORDER BY conversation_type
    ''', (user_id,))
    conversation_types = [row[0] for row in cursor.fetchall()]

    # Get chat history based on filter
    if selected_type == 'all':
        cursor.execute('''
            SELECT * FROM chat_history 
            WHERE user_id = ? 
            ORDER BY timestamp DESC
        ''', (user_id,))
    else:
        cursor.execute('''
            SELECT * FROM chat_history 
            WHERE user_id = ? AND conversation_type = ?
            ORDER BY timestamp DESC
        ''', (user_id, selected_type))

    chat_history = cursor.fetchall()
    conn.close()

    return render_template('history.html',
                           chat_history=chat_history,
                           conversation_types=conversation_types,
                           selected_type=selected_type,
                           username=session['username'])


@app.route('/logout')
def logs_out():
    """Log out the user"""
    session.clear()
    return redirect('/')


@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    """Format datetime for templates"""
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value
    return value.strftime(format)


if __name__ == '__main__':
    app.run(debug=True)