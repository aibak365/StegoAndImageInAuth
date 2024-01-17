"""

███████╗████████╗███████╗ ██████╗  ██████╗     ███████╗ ██████╗ ██████╗      █████╗ ██╗   ██╗████████╗██╗  ██╗
██╔════╝╚══██╔══╝██╔════╝██╔════╝ ██╔═══██╗    ██╔════╝██╔═══██╗██╔══██╗    ██╔══██╗██║   ██║╚══██╔══╝██║  ██║
███████╗   ██║   █████╗  ██║  ███╗██║   ██║    █████╗  ██║   ██║██████╔╝    ███████║██║   ██║   ██║   ███████║
╚════██║   ██║   ██╔══╝  ██║   ██║██║   ██║    ██╔══╝  ██║   ██║██╔══██╗    ██╔══██║██║   ██║   ██║   ██╔══██║
███████║   ██║   ███████╗╚██████╔╝╚██████╔╝    ██║     ╚██████╔╝██║  ██║    ██║  ██║╚██████╔╝   ██║   ██║  ██║
╚══════╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
                                                                                                              
Author: Black_pixles
"""



import math
import numpy as np
import base64
import binascii
import imghdr
from django.shortcuts import render,redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from PIL import Image
import io
import hashlib
from PIL import Image
from django.contrib.auth.decorators import login_required
from app.models import User
from .form import RegistrationForm
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from django.contrib.auth import logout
import hashlib
from channels.generic.websocket import AsyncWebsocketConsumer
from django.http import HttpResponse
import numpy as np
import math

# Generate a random 32-byte key and convert it to a string
def keyString():
    key = base64.b64encode(os.urandom(16)).decode('utf-8')
    return key

#Xor between 2 hashes
def xor_hashes(hash1, hash2):
    # Convert the hashes from hexadecimal to bytes
    hash1_bytes = bytes.fromhex(hash1)
    hash2_bytes = bytes.fromhex(hash2)

    # XOR the two hashes and return the result
    xor_result = bytes(a ^ b for a, b in zip(hash1_bytes, hash2_bytes))
    return binascii.hexlify(xor_result).decode()

#Compute the digeest of a string
def hash_string(input_string):
    # Create a new sha256 hash object
    sha_signature = hashlib.sha256(input_string.encode()).hexdigest()
    return sha_signature

#Calculate the digest of the imgae
def image_digest(image_data):
    # Read the image data
    data = image_data.tobytes()
    # Calculate the hash
    hash_object = hashlib.sha256(data)
    hex_dig = hash_object.hexdigest()
    return hex_dig

#Check if the file is image
def is_image(file):
    image_types = [ 'jpeg', 'png']
    return imghdr.what(file) in image_types

#Hiding data into img by LSB
def LSB(image, msg):
    # Convert the message to binary
    binary_message = ''.join(format(ord(i), '08b') for i in msg)
    
    # Calculate the total number of bits that can be hidden in the image
    total_bits = image.width * image.height * len(image.getpixel((0, 0)))
    
    # Check if the binary_message is too long for the image
    if len(binary_message) > total_bits:
        raise ValueError("The message is too long to be hidden in the image.")
    
    # Convert the image to a NumPy array for efficient manipulation
    np_image = np.array(image)
    
    # Iterate over the pixels in the image
    message_index = 0
    for y in range(image.height):
        for x in range(image.width):
            # Get the current pixel
            pixel = np_image[y, x]

            # Modify the pixel to contain the message
            for n in range(len(pixel)):
                if message_index < len(binary_message):
                    # Change the least significant bit of each color component
                    pixel[n] = pixel[n] & ~1 | int(binary_message[message_index])
                    message_index += 1

            # Write the modified pixel to the output image
            np_image[y, x] = pixel

    # Convert the NumPy array back to an image
    output_image = Image.fromarray(np_image)

    # Return the output image
    return output_image
#To extract the hidden key in the image
def extract_LSB(image):
    # Convert the image to a numpy array
    image_array = np.array(image)

    # Extract the least significant bit of each color component
    lsb_array = np.bitwise_and(image_array, 1)

    # Convert the binary message to a string
    binary_message = ''.join(map(str, lsb_array.flatten()))

    # Convert the binary message to text
    output_message = ''.join(chr(int(binary_message[i:i+8], 2)) for i in range(0, len(binary_message), 8))

    # Find the start and end of the hidden message
    start = output_message.find("#####")
    end = output_message.find("$$$$$")

    # Extract the hidden message
    if start != -1 and end != -1:
        output_message = output_message[start+5:end]
    else:
        output_message = "No hidden message found in the image."

    # Return the output message
    return output_message

#Calculate the image of the size
def check_image_size(image):
    size = image.size
    size_in_MB = size / (1024 * 1024)  # Convert size to MB
    return size_in_MB

# This code is not part of the project, this just to show in front of the commitee the value of the PSNR
def calculate_psnr(img1, img2):
    # Convert the PIL Image objects to NumPy arrays
    img1 = np.array(img1)
    img2 = np.array(img2)

    # Ensure the images are in the range [0, 255]
    img1 = img1.astype(np.float64)
    img2 = img2.astype(np.float64)

    # Calculate the Mean Squared Error between the two images
    mse = np.mean((img1 - img2) ** 2)
    if mse == 0:
        return float('inf')

    # Assuming the maximum pixel value is 255
    max_pixel = 255.0
    psnr = 20 * math.log10(max_pixel / math.sqrt(mse))
    return psnr
     
#Here is the register process
def register(request):
    if request.method == 'POST':
        #Checking email
        email = str(request.POST['email'])
        email = email.lower()
        if User.objects.filter(email=email).exists():
                    messages.info(request, 'Email already has been used!')
                    return redirect('register')
        for i in email:
            if (i<'A' or i>'Z') and (i<'a' or i>'z') and (i<'0' or i>'9') and i not in  ['_', '.','@']:
                messages.info(request,"please enter a valide mail: only contain alphapets and numbers")
                return redirect('register')
              
        #Creating form
        # the rest of the code is not in the image
        form = RegistrationForm(request.POST) 
        if form.is_valid():
            user = form.save(commit=False)

            #Checking Image
            if 'image1' in request.FILES :
                image1 = request.FILES['image1']
            else:
                messages.info(request,"Please enter a correct imgae1")
                return redirect('register')
            
            if 'image2' in request.FILES :
                image2 = request.FILES['image2']
            else:
                messages.info(request,"Please enter a correct imgae2")
                return redirect('register')
            
            if 'image3' in request.FILES:
                image3 = request.FILES['image3']
            else:
                messages.info(request,"Please enter a correct imgae3")
                return redirect(request,'register')
            
            if not is_image(image1) or check_image_size(image1)>8:
                messages.info(request,"Please enter a correct imgae1")
                return redirect('register')
            
            if not is_image(image2) or check_image_size(image2)>8:
                messages.info("Please enter a correct imgae2")
                return redirect(request,'register')
            
            if not is_image(image3) or check_image_size(image3)>8:
                messages.info(request,"Please enter a correct imgae3")
                return redirect('register')
            
            #Checking Password
            password=request.POST['password']
            confirm=request.POST['confirm']

            if password != confirm:
                messages.info(request, 'Unmatch passwords')
                return redirect('register')
            
            cnt_strength_password_capital = True
            cnt_strength_password_lower = True
            cnt_strength_password_special = True
            cnt_strength_password_number = True
            cnt_strength_password_len = 0

            for i in password:
                if i>='A' and i<='Z':
                    cnt_strength_password_capital = False
                elif i>='a' and i<='z':
                    cnt_strength_password_lower = False
                elif i in ['!','@','#','$','%','^','&','*','(',')','-','_','+','=']:
                    cnt_strength_password_special = False
                elif i>='0' and i<='9':
                    cnt_strength_password_number = False
                cnt_strength_password_len+=1
            
            if cnt_strength_password_len<8 or ( cnt_strength_password_capital or  cnt_strength_password_lower or  cnt_strength_password_special or cnt_strength_password_number):
                messages.info(request,"Please pick a better password contains: 8 chars, lower, capital, special and a number")
                return redirect('register')
            password_hash = hash_string(password)

            # Read the images into memory
            image1_data = Image.open(io.BytesIO(image1.read()))
            image2_data = Image.open(io.BytesIO(image2.read()))
            image3_data = Image.open(io.BytesIO(image3.read()))

            #Hiding by LSB R1 && calculating the digest of stego image
            try:
                stego_image1_R1 = LSB(image1_data,password_hash)
                stego_digest1_R1 = image_digest(stego_image1_R1)
                print(calculate_psnr(stego_image1_R1,image1_data))
            except:
                messages.info(request,"Please pick a better image")
                return redirect("register")

            #Hiding by LSB R2 && calculateing the digest and of stego2 
            try:
                stego_image2_R2 = LSB(image2_data,stego_digest1_R1)
            except:
                messages.info(request,"Please pick a better image")
                return redirect("register")
            
            
            #Hiding by LSB the stego_key && calculateing the digest and of stego3
            try:
                keyHided = keyString()
                stego_image3_R3 = LSB(image3_data,image_digest(stego_image2_R2)+"#####"+keyHided+"$$$$$")
                stego_digest3_R3 = image_digest(stego_image3_R3)
            except:
                messages.info(request,"Please pick a better image")
                return redirect("register")
            
            #Saving the user in the database    
            xor=xor_hashes(stego_digest3_R3,password_hash)
            user.set_password(hash_string(xor))
            user.email = email
            user.clientKey = keyHided
            user.save() 

            #Handle the image for the user
            image_io = io.BytesIO()
            stego_image3_R3.save(image_io, format='PNG')

            # Create a base64 string of the image data
            image_str = base64.b64encode(image_io.getvalue()).decode('utf-8')

            # Create a data URL of the image
            data_url = 'data:image/png;base64,' + image_str

            # Pass the data URL to the template
            return render(request, 'yourStego.html', {'image_data_url': data_url})
        else:
            messages.info(request, "Please enter a valid email")

    else:
        form = RegistrationForm()

    return render(request, 'register.html', {'form': form})

#Here is the login process, note (we made the function called log_in to avoid overload, pls keep it like that)
def log_in(request):
    if request.method == 'POST':
            password = str(request.POST['password'])            
            #Checking email
            email = request.POST['email']
            for i in email:
                if (i<'A' or i>'Z') and (i<'a' or i>'z') and (i<'0' or i>'9') and i not in  ['_', '.','@']:
                    messages.info(request,"please enter a valide mail: only contain alphapets and numbers")
                    return redirect('login')
            if 'image1' in request.FILES:
                image1 = request.FILES['image1']
                if is_image(image1):
                    try:
                        image1_data = Image.open(io.BytesIO(image1.read()))
                    except:
                        messages.info(request,"Invalid image")
                        return redirect("log_in")
                    password_hash = hash_string(password)
                    image1_digest = image_digest(image1_data)
                    xor_hash = hash_string(xor_hashes(image1_digest,password_hash))
                    user = authenticate(request, username=email, password=xor_hash) 
                    yourKey = extract_LSB(image1_data)
                    if user is not None and yourKey == user.clientKey:
                        login(request,user)
                        return redirect('hello') 
                    else:
                        messages.info(request,"Invalid emair or credentials")
                        return redirect('log_in')             
                else:
                    messages.info("Please upload jpg or png image only")
                    return redirect('log_in')
            else:
                messages.info(request,'No image file uploaded')
                return redirect('log_in')
    return render(request, 'log_in.html')


#The index page
def index(request):
    return render(request, "index.html")

#A hello page
@login_required
def hello(request):
    return render(request, 'hello.html')

