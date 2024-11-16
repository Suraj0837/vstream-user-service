import json
import traceback
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import User
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from uuid import uuid4
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import AuthenticationFailed

@csrf_exempt  # Disable CSRF for testing, for production, use proper CSRF protection
def register_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            # Extract user data from request
            name = data.get('name')
            dob = data.get('dob')
            email = data.get('email')
            password = data.get('password')

            # Check if all fields are provided
            if not all([name, dob, email, password]):
                return JsonResponse({'error': 'All fields are required'}, status=400)

            # Create a unique ID
            user_id = str(uuid4())

            # Hash password using bcrypt
            hashed_password = make_password(password)

            # Create the user instance
            user = User.objects.create(
                id=user_id,
                full_name=name,
                date_of_birth=dob,
                email=email,
                password=hashed_password,
                created_on=timezone.now(),
                modified_on=timezone.now()
            )

            # Return success response
            return JsonResponse({'message': 'User registered successfully', 'user_id': user_id}, status=201)
        except json.JSONDecodeError as e:
            # Print stack trace for JSONDecodeError
            print("Error occurred while parsing JSON data:")
            traceback.print_exc()  # This will print the full stack trace to the console
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
        except Exception as e:
            # Catch any other exceptions and print their stack trace
            print("An unexpected error occurred:")
            traceback.print_exc()  # This will print the full stack trace to the console
            return JsonResponse({'error': 'An unexpected error occurred'}, status=500)

    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

@csrf_exempt
def login_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            # Extract username and password from request
            username = data.get('username')
            password = data.get('password')

            # Check if both fields are provided
            if not username or not password:
                return JsonResponse({'error': 'Username and password are required'}, status=400)

            # Check if the user exists
            try:
                user = User.objects.get(email=username)
            except User.DoesNotExist:
                return JsonResponse({'error': 'Invalid username or password'}, status=401)

            # Verify the password
            if not check_password(password, user.password):
                return JsonResponse({'error': 'Invalid username or password'}, status=401)

            # Generate JWT token
            refresh = RefreshToken.for_user(user)

            # Return the token and success response
            return JsonResponse({
                'message': 'Login successful',
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'username': str(username),
            }, status=200)

        except json.JSONDecodeError as e:
            print("Error occurred while parsing JSON data:")
            traceback.print_exc()
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
        except Exception as e:
            print("An unexpected error occurred:")
            traceback.print_exc()
            return JsonResponse({'error': 'An unexpected error occurred'}, status=500)

    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)

@csrf_exempt
def authorize_user(request):
    """
    API to validate Bearer token from Authorization header.
    """
    if request.method == 'POST':
        try:
            # Extract Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header missing or invalid'}, status=401)

            # Extract the token
            token = auth_header.split(' ')[1]

            # Validate the token
            try:
                decoded_token = AccessToken(token)
                user_id = decoded_token['user_id']  # Assuming `user_id` is in the payload
                return JsonResponse({'message': 'Authorization successful', 'user_id': user_id}, status=200)
            except Exception:
                raise AuthenticationFailed('Invalid or expired token')

        except AuthenticationFailed as e:
            return JsonResponse({'error': str(e)}, status=401)
        except Exception:
            print("An unexpected error occurred during authorization:")
            traceback.print_exc()
            return JsonResponse({'error': 'An unexpected error occurred'}, status=500)

    return JsonResponse({'error': 'Only POST method is allowed'}, status=405)