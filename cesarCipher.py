def cifrado_cesar(texto, corrimiento):
    resultado = ""
    for char in texto:
        if char.isalpha():  # Solo aplicamos a letras
            # Determinar si es mayúscula o minúscula
            base = ord('A') if char.isupper() else ord('a')
            # Aplicar fórmula del corrimiento
            resultado += chr((ord(char) - base + corrimiento) % 26 + base)
        else:
            # Si no es letra, se deja igual (espacios, números, etc.)
            resultado += char
    return resultado


# Programa principal
if __name__ == "__main__":
    texto = input("Ingrese el texto a cifrar: ")
    corrimiento = int(input("Ingrese el valor de corrimiento: "))

    texto_cifrado = cifrado_cesar(texto, corrimiento)
    print("\nTexto cifrado:", texto_cifrado)
