from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
import jwt
import hashlib
import secrets
import random
from datetime import datetime, timedelta
import os
from functools import wraps

app = Flask(__name__)
CORS(app)

# Configuration
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb+srv://cha:zOGl6KbFaDzt1RAF@cluster0.dvo7ddf.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
JWT_SECRET = os.getenv('JWT_SECRET', 'kabhinakabhi892828u8u8uhhjsnjnuwhsuhsu2hiuwhkjb')
DATABASE_NAME = 'Cluster0'

# MongoDB connection
client = MongoClient(MONGODB_URI)
db = client[DATABASE_NAME]

# Word list for passphrase generation
WORD_LIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "against", "age",
    "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army",
    "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma",
    "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit",
    "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid",
    "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby",
    "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo",
    "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef",
    "before", "begin", "behave", "behind", "believe", "below", "belt", "bench",
    "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid",
    "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade",
    "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
    "blow", "blue", "blur", "blush", "board", "boat"
]

def generate_passphrase():
    """Generate a 12-word passphrase"""
    words = random.sample(WORD_LIST, 12)
    return " ".join(words)

def hash_passphrase(passphrase):
    """Hash passphrase using SHA-256"""
    return hashlib.sha256(passphrase.encode()).hexdigest()

def generate_jwt(payload):
    """Generate JWT token"""
    payload['exp'] = datetime.utcnow() + timedelta(days=30)
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise Exception("Token expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")

def auth_required(f):
    """Decorator for routes that require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            token = auth_header.split(' ')[1]
            payload = verify_jwt(token)
            request.user_id = payload['userId']
            request.username = payload['username']
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': str(e)}), 401
    
    return decorated_function

def serialize_doc(doc):
    """Convert MongoDB document to JSON serializable format"""
    if doc is None:
        return None
    if isinstance(doc, list):
        return [serialize_doc(item) for item in doc]
    if isinstance(doc, dict):
        result = {}
        for key, value in doc.items():
            if isinstance(value, ObjectId):
                result[key] = str(value)
            elif isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, (dict, list)):
                result[key] = serialize_doc(value)
            else:
                result[key] = value
        return result
    return doc

# Authentication Routes
@app.route('/auth/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email')
        username = data.get('username')
        
        if not email or not username:
            return jsonify({'error': 'Email and username required'}), 400
        
        # Check if user already exists
        existing_user = db.users.find_one({
            '$or': [{'email': email}, {'username': username}]
        })
        
        if existing_user:
            return jsonify({'error': 'User already exists'}), 409
        
        # Generate passphrase and create user
        passphrase = generate_passphrase()
        hashed_passphrase = hash_passphrase(passphrase)
        
        user = {
            'email': email,
            'username': username,
            'passphrase': hashed_passphrase,
            'createdAt': datetime.utcnow(),
            'watchlist': [],
            'history': [],
            'preferences': {}
        }
        
        db.users.insert_one(user)
        
        return jsonify({'passphrase': passphrase}), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        passphrase = data.get('passphrase')
        
        if not passphrase:
            return jsonify({'error': 'Passphrase required'}), 400
        
        hashed_passphrase = hash_passphrase(passphrase)
        user = db.users.find_one({'passphrase': hashed_passphrase})
        
        if not user:
            return jsonify({'error': 'Invalid passphrase'}), 401
        
        token = generate_jwt({
            'userId': str(user['_id']),
            'username': user['username']
        })
        
        return jsonify({
            'user': {
                'id': str(user['_id']),
                'username': user['username'],
                'email': user['email']
            },
            'token': token
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/verify', methods=['GET'])
@auth_required
def verify_auth():
    try:
        user = db.users.find_one({'_id': ObjectId(request.user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': str(user['_id']),
            'username': user['username'],
            'email': user['email']
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Content Routes
@app.route('/content/trending', methods=['GET'])
def get_trending():
    try:
        # Get most watched content
        trending = list(db.content.find({}).sort([('viewCount', -1), ('createdAt', -1)]).limit(20))
        
        # Transform to simplified format
        simplified_trending = []
        for item in trending:
            simplified_trending.append({
                'id': item.get('id', str(item['_id'])),
                'title': item['title'],
                'image': item.get('image', item.get('poster')),
                'link': item.get('link', f"movie/{item.get('id', str(item['_id']))}"),
                'genres': item.get('genres', [])
            })
        
        return jsonify(simplified_trending), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/content/popular/<content_type>', methods=['GET'])
def get_popular(content_type):
    try:
        popular = list(db.content.find({'type': content_type}).sort('viewCount', -1).limit(20))
        
        # Transform to simplified format
        simplified_popular = []
        for item in popular:
            simplified_popular.append({
                'id': item.get('id', str(item['_id'])),
                'title': item['title'],
                'image': item.get('image', item.get('poster')),
                'link': item.get('link', f"movie/{item.get('id', str(item['_id']))}"),
                'genres': item.get('genres', [])
            })
        
        return jsonify(simplified_popular), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/content/weekly/<day>', methods=['GET'])
def get_weekly_recommendations(day):
    try:
        # Get content based on day-specific algorithm
        day_genres = {
            'monday': ['Action', 'Thriller'],
            'tuesday': ['Comedy', 'Romance'],
            'wednesday': ['Drama', 'Mystery'],
            'thursday': ['Sci-Fi', 'Fantasy'],
            'friday': ['Horror', 'Thriller'],
            'saturday': ['Action', 'Adventure'],
            'sunday': ['Family', 'Animation']
        }
        
        genres = day_genres.get(day, ['Action', 'Drama'])
        recommendations = list(db.content.find({
            'genres': {'$in': genres}
        }).sort('viewCount', -1).limit(15))
        
        # Transform to simplified format
        simplified_recommendations = []
        for item in recommendations:
            simplified_recommendations.append({
                'id': item.get('id', str(item['_id'])),
                'title': item['title'],
                'image': item.get('image', item.get('poster')),
                'link': item.get('link', f"movie/{item.get('id', str(item['_id']))}"),
                'genres': item.get('genres', [])
            })
        
        return jsonify(simplified_recommendations), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/search', methods=['GET'])
def search_content():
    try:
        query = request.args.get('q', '')
        if not query:
            return jsonify([]), 200
        
        results = list(db.content.find({
            '$or': [
                {'title': {'$regex': query, '$options': 'i'}},
                {'genres': {'$elemMatch': {'$regex': query, '$options': 'i'}}}
            ]
        }).limit(50))
        
        # Transform to simplified format
        simplified_results = []
        for item in results:
            simplified_results.append({
                'id': item.get('id', str(item['_id'])),
                'title': item['title'],
                'image': item.get('image', item.get('poster')),
                'link': item.get('link', f"movie/{item.get('id', str(item['_id']))}"),
                'genres': item.get('genres', [])
            })
        
        return jsonify(simplified_results), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# User Routes (require authentication)
@app.route('/user/watchlist', methods=['POST'])
@auth_required
def add_to_watchlist():
    try:
        data = request.get_json()
        movie_id = data.get('movieId')
        
        db.users.update_one(
            {'_id': ObjectId(request.user_id)},
            {'$addToSet': {'watchlist': movie_id}}
        )
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/user/watchlist', methods=['GET'])
@auth_required
def get_user_watchlist():
    try:
        user = db.users.find_one({'_id': ObjectId(request.user_id)})
        if not user or not user.get('watchlist'):
            return jsonify([]), 200
        
        # Convert string IDs to ObjectIds for MongoDB query
        watchlist_ids = []
        for movie_id in user['watchlist']:
            try:
                watchlist_ids.append(ObjectId(movie_id))
            except:
                # If it's not a valid ObjectId, keep as string for 'id' field search
                pass
        
        # Search by both _id and id fields
        watchlist = list(db.content.find({
            '$or': [
                {'_id': {'$in': watchlist_ids}},
                {'id': {'$in': user['watchlist']}}
            ]
        }))
        
        return jsonify(serialize_doc(watchlist)), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/user/track-view', methods=['POST'])
@auth_required
def track_view():
    try:
        data = request.get_json()
        movie_id = data.get('movieId')
        timestamp = data.get('timestamp')
        
        # Add to user history
        db.users.update_one(
            {'_id': ObjectId(request.user_id)},
            {'$push': {
                'history': {
                    'movieId': movie_id,
                    'timestamp': datetime.fromtimestamp(timestamp / 1000),
                    'progress': 0
                }
            }}
        )
        
        # Increment view count
        db.content.update_one(
            {'$or': [{'_id': ObjectId(movie_id)}, {'id': movie_id}]},
            {'$inc': {'viewCount': 1}}
        )
        
        return jsonify({'success': True}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/user/history', methods=['GET'])
@auth_required
def get_user_history():
    try:
        user = db.users.find_one({'_id': ObjectId(request.user_id)})
        if not user or not user.get('history'):
            return jsonify([]), 200
        
        movie_ids = [h['movieId'] for h in user['history']]
        
        # Convert string IDs to ObjectIds where possible
        object_ids = []
        for movie_id in movie_ids:
            try:
                object_ids.append(ObjectId(movie_id))
            except:
                pass
        
        movies = list(db.content.find({
            '$or': [
                {'_id': {'$in': object_ids}},
                {'id': {'$in': movie_ids}}
            ]
        }))
        
        # Add progress information
        history_with_progress = []
        for movie in movies:
            movie_id = movie.get('id', str(movie['_id']))
            history_item = next((h for h in user['history'] if h['movieId'] == movie_id), None)
            
            movie_data = serialize_doc(movie)
            movie_data['progress'] = history_item.get('progress', 0) if history_item else 0
            movie_data['lastWatched'] = history_item.get('timestamp').isoformat() if history_item and history_item.get('timestamp') else None
            
            history_with_progress.append(movie_data)
        
        return jsonify(history_with_progress), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/user/recommendations', methods=['GET'])
@auth_required
def get_recommendations():
    try:
        user = db.users.find_one({'_id': ObjectId(request.user_id)})
        if not user or not user.get('history'):
            # Return popular content for new users
            return get_trending()
        
        # Simple recommendation based on user's viewing history
        watched_genres = []
        for history_item in user['history']:
            movie = db.content.find_one({
                '$or': [
                    {'_id': ObjectId(history_item['movieId'])},
                    {'id': history_item['movieId']}
                ]
            })
            if movie and movie.get('genres'):
                watched_genres.extend(movie['genres'])
        
        # Get most common genres
        genre_counts = {}
        for genre in watched_genres:
            genre_counts[genre] = genre_counts.get(genre, 0) + 1
        
        top_genres = sorted(genre_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        top_genres = [genre for genre, count in top_genres]
        
        # Get watched movie IDs
        watched_ids = [h['movieId'] for h in user['history']]
        watched_object_ids = []
        for movie_id in watched_ids:
            try:
                watched_object_ids.append(ObjectId(movie_id))
            except:
                pass
        
        recommendations = list(db.content.find({
            'genres': {'$in': top_genres},
            '$and': [
                {'_id': {'$nin': watched_object_ids}},
                {'id': {'$nin': watched_ids}}
            ]
        }).sort([('rating', -1), ('viewCount', -1)]).limit(20))
        
        return jsonify(serialize_doc(recommendations)), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/user/continue-watching', methods=['GET'])
@auth_required
def get_continue_watching():
    try:
        user = db.users.find_one({'_id': ObjectId(request.user_id)})
        if not user or not user.get('history'):
            return jsonify([]), 200
        
        # Get recently watched items with progress < 90%
        recent_history = [h for h in user['history'] if h.get('progress', 0) < 90]
        recent_history.sort(key=lambda x: x.get('timestamp', datetime.min), reverse=True)
        recent_history = recent_history[:10]
        
        movie_ids = [h['movieId'] for h in recent_history]
        object_ids = []
        for movie_id in movie_ids:
            try:
                object_ids.append(ObjectId(movie_id))
            except:
                pass
        
        movies = list(db.content.find({
            '$or': [
                {'_id': {'$in': object_ids}},
                {'id': {'$in': movie_ids}}
            ]
        }))
        
        continue_watching = []
        for movie in movies:
            movie_id = movie.get('id', str(movie['_id']))
            history_item = next((h for h in recent_history if h['movieId'] == movie_id), None)
            
            movie_data = serialize_doc(movie)
            movie_data['progress'] = history_item.get('progress', 0) if history_item else 0
            
            continue_watching.append(movie_data)
        
        return jsonify(continue_watching), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Create indexes for better performance
    try:
        db.users.create_index('email', unique=True)
        db.users.create_index('username', unique=True)
        db.users.create_index('passphrase', unique=True)
        db.content.create_index('title')
        db.content.create_index('genres')
        db.content.create_index('viewCount')
        db.content.create_index('id')
        print("Database indexes created successfully")
    except Exception as e:
        print(f"Index creation warning: {e}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
