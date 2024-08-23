

sum = ''

def addition(n):
    global sum  # Declare 'sum' as a global variable
    i = 5

    if i == 5:
        sum += str(i)  # Convert 'i' to a string before concatenating with 'sum'
        return i

print('the sum is', sum)
print(addition(2))