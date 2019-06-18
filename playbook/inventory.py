import this
bicycles = ['trek','cannondale','redline','specialized']
#sort items in list
bicycles.sort()
bicycles.sort(reverse=True)
sorted(bicycles)
bicycles.reverse()
print(len(bicycles))
print(bicycles)
#print first item
print(bicycles[0])
#print latest item
print(bicycles[-1])
motorcycles=['honda','yamaha','suzuki']
#modify first item
motorcycles[0]='ducati'
#append item
motorcycles.append('ducati')
#insert item by indix
motorcycles.insert(1,'ducati1')
#delete latest item by del
del motorcycles[-1]
#delete latest item by pop method
motorcycles.pop()
#delete first item by pop(index)
motorcycles.pop(0)
#delete item by value
motorcycles.remove('ducati1')

print(motorcycles)
for m in motorcycles:
    print(m)
dimensions=(200,50)
print(dimensions[0])
print(dimensions[1])