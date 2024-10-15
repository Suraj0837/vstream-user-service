from django.shortcuts import render, redirect
from .forms import UserRegistrationForm

def register_user(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.password = form.cleaned_data['password']  # In practice, hash this password
            user.save()
            return redirect('registration_success')
    else:
        form = UserRegistrationForm()
    return render(request, 'register.html', {'form': form})
