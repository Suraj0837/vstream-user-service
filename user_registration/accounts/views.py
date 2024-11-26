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
            refresh['username'] = user.email  # Add username
            refresh['full_name'] = user.full_name


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

@csrf_exempt
def modify_user(request):
    """
    API to modify user details except email.
    The user must be authenticated using a valid token.
    """
    if request.method == 'PUT':
        try:
            # Extract Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header missing or invalid'}, status=401)

            # Extract and validate the token
            token = auth_header.split(' ')[1]
            try:
                decoded_token = AccessToken(token)
                user_id = decoded_token['user_id']
            except Exception:
                raise AuthenticationFailed('Invalid or expired token')

            # Fetch the user from the database
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User does not exist'}, status=404)

            # Parse request data
            data = json.loads(request.body)
            name = data.get('name')
            dob = data.get('dob')
            password = data.get('password')

            # Update fields if provided
            if name:
                user.full_name = name
            if dob:
                user.date_of_birth = dob
            if password:
                user.password = make_password(password)

            user.modified_on = timezone.now()
            user.save()

            return JsonResponse({'message': 'User details updated successfully'}, status=200)

        except AuthenticationFailed as e:
            return JsonResponse({'error': str(e)}, status=401)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
        except Exception:
            print("An unexpected error occurred during modification:")
            traceback.print_exc()
            return JsonResponse({'error': 'An unexpected error occurred'}, status=500)

    return JsonResponse({'error': 'Only PUT method is allowed'}, status=405)

@csrf_exempt
def delete_user(request):
    """
    API to delete a user. The user must be authenticated using a valid token.
    """
    if request.method == 'DELETE':
        try:
            # Extract Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Authorization header missing or invalid'}, status=401)

            # Extract and validate the token
            token = auth_header.split(' ')[1]
            try:
                decoded_token = AccessToken(token)
                user_id = decoded_token['user_id']
            except Exception:
                raise AuthenticationFailed('Invalid or expired token')

            # Fetch the user from the database
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User does not exist'}, status=404)

            # Delete the user
            user.delete()
            return JsonResponse({'message': 'User deleted successfully'}, status=200)

        except AuthenticationFailed as e:
            return JsonResponse({'error': str(e)}, status=401)
        except Exception:
            print("An unexpected error occurred during deletion:")
            traceback.print_exc()
            return JsonResponse({'error': 'An unexpected error occurred'}, status=500)

    return JsonResponse({'error': 'Only DELETE method is allowed'}, status=405)

@csrf_exempt
def get_full_name(request):
    """
    API to fetch the full name of a user by their user_id from query parameters.
    Example: GET /get_full_name/?user_id=<user_id>
    """
    if request.method == 'GET':
        try:
            # Get user_id from query parameters
            user_id = request.GET.get('user_id')

            if not user_id:
                return JsonResponse({'error': 'user_id query parameter is required'}, status=400)

            # Fetch the user from the database
            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User not found'}, status=404)

            # Return the full name and user_id
            return JsonResponse({
                'user_id': user.id,
                'full_name': user.full_name
            }, status=200)

        except Exception as e:
            print("An unexpected error occurred while fetching the full name:")
            traceback.print_exc()
            return JsonResponse({'error': 'An unexpected error occurred'}, status=500)

    return JsonResponse({'error': 'Only GET method is allowed'}, status=405)
