#obtener qtree
#función para obtener shared /qtree
    #input: 
        #  nombre del bucket de s3
    #output: 
        # shared
        # qtree
        # ruta completa (shared/qtree)
    # lo que tiene que hacer:
        # 1. a partir del nombre del bucket de s3, obtener shared y qtree. 
            # 1.1 shared = las primeras letras hasta llegar a un guión (ex: nombre del bucket = ccl-proyectoprueba-worm --> shared = ccl)
            # 1.2 qtree = las letras + caracteres restantes después del guión y sin el -worm del final (ex: nombre del bucket = ccl-proyectoprueba-1-worm --> qtree = proyectoprueba-1)
        # 2. retornar shared, qtree y ruta completa (shared/qtree)

# montaje
# función para montar un qtree netapp en windows
    #input:
        # ruta completa (shared/qtree)
    #output:
        # ruta montada
    # lo que tiene que hacer:
    # 1. a partir del nombre del shared y qtree, montar ese qtree de Netapp en windows. Condiciones:
        # 1.1 Montarlo en la ruta: \\ ... (importante solo montar el qtree, no todo el shared)
        # 1.2 El acceso tiene que ser de lectura y escritura. Por lo tanto, tiene que tener file locking y para eso no se puede hacer con rclone (el fichero se queda corrupto si dos personas lo modifican a la vez, porque no tienen file locking)
        # 1.3 Para montar qtree, quizas usar smb mejor


# función para montar qtree netapp en mac
    #input:
        # ruta completa (shared/qtree)
    #output:
        # ruta montada

# función para montar qtree en ood
    #input:
        # ruta completa (shared/qtree)
    #output:
        # ruta montada


# desmontaje
# función para desmontar un qtree netapp en windows
    #input: 
        # ruta montada
    #output:    

# función para desmontar un qtree netapp en mac
    #input: 
        # ruta montada
    #output:   

# función para desmontar un qtree netapp en ood
    #input: 
        # ruta montada
    #output:   