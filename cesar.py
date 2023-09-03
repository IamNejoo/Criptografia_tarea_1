def cifrado_cesar(texto, corrimiento):
    resultado = ""

    for caracter in texto:
        if caracter.isalpha():
            mayuscula = caracter.isupper()
            caracter = caracter.lower()
            codigo = ord(caracter)
            codigo_cifrado = ((codigo - 97 + corrimiento) % 26) + 97
            if mayuscula:
                resultado += chr(codigo_cifrado).upper()
            else:
                resultado += chr(codigo_cifrado)
        else:
            resultado += caracter

    return resultado

texto_original = input("Ingrese el texto a cifrar: ")
corrimiento = int(input("Ingrese el valor de corrimiento (un número entero): "))

texto_cifrado = cifrado_cesar(texto_original, corrimiento)
print("Texto cifrado:", texto_cifrado)
