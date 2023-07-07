from django.http import HttpResponse
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
# from django.utils.encoding import force_bytes, force_text
from rest_framework import generics, status
from rest_framework.response import Response
from .serializers import RegisterSerializer,LoginSerializer
from django.contrib.auth import authenticate,login,logout
from rest_framework.authtoken.models import Token
from django.contrib.auth.hashers import make_password


# from .tokens import account_activation_token

User = get_user_model()

# Create your views here.
def index(request):
    return HttpResponse("index page")

class SignUpView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # # Email Verification
        # current_site = get_current_site(request)
        # mail_subject = 'Activate your account'
        # message = render_to_string(
        #     'account_activation_email.html',
        #     {
        #         'user': user,
        #         'domain': current_site.domain,
        #         'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        #         'token': account_activation_token.make_token(user),
        #     }
        # )
        # send_mail(mail_subject, message, 'from@example.com', [user.email])

        return Response({'message': 'User created successfully. Please check your email to verify your account.'},
                        status=status.HTTP_201_CREATED)


# class EmailVerificationView(generics.GenericAPIView):
#     def get(self, request, token, *args, **kwargs):
#         try:
#             uid = force_text(urlsafe_base64_decode(token))
#             user = User.objects.get(pk=uid)
#             user.is_active = True
#             user.save()
#             return Response({'message': 'Email verification successful.'}, status=status.HTTP_200_OK)
#         except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#             return Response({'message': 'Invalid verification token.'}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Perform any additional logic after successful login

        return Response({'message': 'Login successful.'})