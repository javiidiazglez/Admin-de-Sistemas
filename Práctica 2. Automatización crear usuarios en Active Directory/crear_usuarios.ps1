param (
    [Parameter(Mandatory=$false)]
    [string]$RutaCSV
)

# Verificar si se está ejecutando como administrador
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este script requiere privilegios de administrador."
    exit 1
} else {
    Write-Host "----------------- Privilegios Admin -----------------------"
}

# Verificar si se especificó la ruta del CSV
if ([string]::IsNullOrEmpty($RutaCSV)) {
    Write-Host "Error: No especifica parametro. Uso correcto: powershell -EP Bypass -F J:\crear_usuarios.ps1 -RutaCSV J:\pruebas.csv"
    exit 1
}

# Verificar que el archivo CSV existe
if (-not (Test-Path $RutaCSV)) {
    Write-Host "Error: El archivo CSV no existe en la ruta especificada: $RutaCSV"
    Write-Host "Uso correcto: powershell -EP Bypass -F J:\crear_usuarios.ps1 -RutaCSV J:\pruebas.csv"
    exit 1
}

# Importar módulo de Active Directory
Import-Module ActiveDirectory 

# Intentar obtener el dominio actual
try {
    $dominio = Get-ADDomain -ErrorAction Stop
    Write-Host "====================================================================="
    Write-Host "Conexión con dominio de Active Directory establecida correctamente."
    Write-Host "====================================================================="
} catch {
    Write-Host "====================================================================="
    Write-Host "Error: '$($_.Exception.Message)'"
    Write-Host "Este script requiere acceso a un dominio de Active Directory configurado."
    Write-Host "====================================================================="
    exit 1
}

Write-Host "====================================================================="
Write-Host "José Javier Díaz González. Administración de Sistemas"
Write-Host "Ejecutando script de creación de usuarios en el dominio: '$($dominio.DNSRoot)'"
Write-Host "Nombre distinguido del dominio: '$($dominio.DistinguishedName)'"
Write-Host "====================================================================="

Write-Host "Procesando el archivo CSV: $RutaCSV"
Write-Host "=========================================================="

# Importar el contenido del CSV
$usuarios = Import-Csv -Path $RutaCSV

# Rastrear usuarios ya procesados
$usuariosProcesados = @{}

# Procesar cada usuario del CSV
foreach ($usuario in $usuarios) {
    $nombreUsuario = $usuario.nombre_usuario
    $unidadOrganizativa = $usuario.unidad_organizativa
    
    # Verificar si ya procesamos este usuario
    if ($usuariosProcesados.ContainsKey($nombreUsuario)) {
        Write-Host "ERROR: Usuario duplicado '$nombreUsuario'. Ya fue asignado a la OU '$($usuariosProcesados[$nombreUsuario])'. No se puede mover a la OU '$unidadOrganizativa'."
        Write-Host "----------------------------------------"
        continue
    }
    
    Write-Host "- Usuario: $nombreUsuario"
    
    # Verificar si el usuario ya existe
    $usuarioExiste = Get-ADUser -Filter "SamAccountName -eq '$nombreUsuario'" -ErrorAction SilentlyContinue
    
    if ($usuarioExiste) {
        Write-Host "    El usuario '$nombreUsuario' ya existe en el dominio '$($dominio.DNSRoot)'"
    } else {
        Write-Host "    El usuario '$nombreUsuario' no existe, creándolo..."
        
        # Crear el usuario
        New-ADUser -SamAccountName $nombreUsuario `
                  -UserPrincipalName "$nombreUsuario@$($dominio.DNSRoot)" `
                  -Name $nombreUsuario `
                  -DisplayName $nombreUsuario `
                  -GivenName $nombreUsuario `
                  -Surname "" `
                  -Enabled $true `
                  -ChangePasswordAtLogon $false `
                  -AccountPassword (ConvertTo-SecureString $nombreUsuario -AsPlainText -Force) `
                  -Path "CN=Users,$($dominio.DistinguishedName)"
        
        Write-Host "    Usuario '$nombreUsuario' creado en 'CN=Users,$($dominio.DistinguishedName)'"
        
        # Actualizar la variable después de crear el usuario
        $usuarioExiste = Get-ADUser -Filter "SamAccountName -eq '$nombreUsuario'" -ErrorAction SilentlyContinue
    }
    # Definir la ruta base para los directorios home
    $rutaBaseHome = "\\CD1JT14FILESERV\personal\casa"
    
    # Configurar el directorio home del usuario
    if ($usuarioExiste) {
        $rutaHomeUsuario = "$rutaBaseHome\$nombreUsuario"
        
        Write-Host "    Configurando directorio \home en '$rutaHomeUsuario' (unidad N:)..."
        
        # Verificar si el directorio home existe, si no, crearlo
        $directorioExiste = Test-Path -Path $rutaHomeUsuario
        if (-not $directorioExiste) {
            Write-Host "        Creando directorio home en '$rutaHomeUsuario'..."
            New-Item -Path $rutaHomeUsuario -ItemType Directory -Force | Out-Null
            Write-Host "        Directorio '$rutaHomeUsuario' creado exitosamente"
            
            # Obtener el ACL actual
            $acl = Get-Acl -Path $rutaHomeUsuario
            
            # Deshabilitar la herencia y eliminar todos los permisos heredados
            $acl.SetAccessRuleProtection($true, $false)
            
            # Agregar permisos para Administradores (control total)
            $adminSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
            $adminAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $adminSID, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
            )
            $acl.AddAccessRule($adminAccessRule)
            
            # Agregar permisos para SYSTEM (control total)
            $systemSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
            $systemAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $systemSID, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
            )
            $acl.AddAccessRule($systemAccessRule)
            
            # Agregar permisos para el usuario específico (control total)
            $userSID = (Get-ADUser -Identity $nombreUsuario).SID
            $userAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $userSID, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
            )
            $acl.AddAccessRule($userAccessRule)
            
            # Aplicar los nuevos permisos
            Set-Acl -Path $rutaHomeUsuario -AclObject $acl
            Write-Host "        Permisos configurados para '$nombreUsuario' con CT en '$rutaHomeUsuario'"
        } else {
            Write-Host "        El directorio home '$rutaHomeUsuario' ya existe"
            
            # Verificar si el usuario ya tiene los permisos adecuados
            $acl = Get-Acl -Path $rutaHomeUsuario
            $userSID = (Get-ADUser -Identity $nombreUsuario).SID
            $tienePermiso = $false
            
            # Verificar si el usuario específico ya tiene permisos en la carpeta
            foreach ($acceso in $acl.Access) {
                if ($acceso.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $userSID.Value -and 
                    $acceso.FileSystemRights -match "FullControl") {
                    $tienePermiso = $true
                    break
                }
            }
            
            if (-not $tienePermiso) {
                Write-Host "        El usuario '$nombreUsuario' no tiene permisos con CT, configurando..."
                
                # Conservar ACL existente pero agregar permisos para el usuario
                $userAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $userSID, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                )
                $acl.AddAccessRule($userAccessRule)
                
                # Aplicar los permisos actualizados
                Set-Acl -Path $rutaHomeUsuario -AclObject $acl
                Write-Host "        Permisos con CT para '$nombreUsuario' en '$rutaHomeUsuario'"
            } else {
                Write-Host "        El usuario '$nombreUsuario' ya tiene permisos con CT"
            }
        }
        
        # Configurar el perfil de usuario en AD para usar este directorio y la unidad N:
        Set-ADUser -Identity $nombreUsuario -HomeDirectory $rutaHomeUsuario -HomeDrive "N:"
        Write-Host "        Usuario '$nombreUsuario' configurado con directorio home en unidad N: ($rutaHomeUsuario)"
    }

    # Si se especificó una unidad organizativa, verificar si existe
    if ($unidadOrganizativa -and $unidadOrganizativa.Trim() -ne "") {
        # Verificar si la unidad organizativa existe
        $ouPath = "OU=$unidadOrganizativa,$($dominio.DistinguishedName)"
        $ouExiste = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouPath'" -ErrorAction SilentlyContinue
        
        if (-not $ouExiste) {
            Write-Host "    La unidad organizativa '$unidadOrganizativa' no existe, creándola..."
            New-ADOrganizationalUnit -Name $unidadOrganizativa -Path $dominio.DistinguishedName
        } else {
            Write-Host "    La unidad organizativa '$unidadOrganizativa' ya existe"
        }
        
        # Mover el usuario a la OU especificada si no está ya allí y si el usuario existe
        if ($usuarioExiste -and $usuarioExiste.DistinguishedName -notlike "*OU=$unidadOrganizativa*") {
            Write-Host "    Moviendo usuario '$nombreUsuario' a la OU '$unidadOrganizativa'..."
            Move-ADObject -Identity $usuarioExiste.DistinguishedName -TargetPath "OU=$unidadOrganizativa,$($dominio.DistinguishedName)"
            Write-Host "    Usuario '$nombreUsuario' movido a la OU '$unidadOrganizativa'"
        } elseif ($usuarioExiste) {
            Write-Host "    El usuario '$nombreUsuario' ya está en la OU '$unidadOrganizativa'"
        }
    }
    # Procesar los grupos para este usuario
    $propiedades = $usuario.PSObject.Properties
    
    # Iterar a través de todas las propiedades del objeto de usuario
    foreach ($propiedad in $propiedades) {
        # Ignorar las propiedades nombre_usuario y unidad_organizativa, procesar todas las demás como grupos
        if ($propiedad.Name -ne "nombre_usuario" -and $propiedad.Name -ne "unidad_organizativa") {
            $nombreGrupo = $propiedad.Value
            
            Write-Host "    Grupo: '$nombreGrupo'"
            
            # Verificar si el grupo existe
            $grupoExiste = Get-ADGroup -Filter "Name -eq '$nombreGrupo'" -ErrorAction SilentlyContinue
            
            if (-not $grupoExiste) {
                Write-Host "        El grupo '$nombreGrupo' no existe, creándolo como grupo global..."
                # Crear el grupo como grupo global
                New-ADGroup -Name $nombreGrupo `
                           -GroupScope Global `
                           -GroupCategory Security `
                           -Path "CN=Users,$($dominio.DistinguishedName)"
                Write-Host "        Grupo global '$nombreGrupo' creado en 'CN=Users,$($dominio.DistinguishedName)'"
            } else {
                Write-Host "        El grupo global '$nombreGrupo' ya existe"
            }
            
            # Verificar si el usuario ya es miembro del grupo
            $esMiembro = Get-ADGroupMember -Identity $nombreGrupo -ErrorAction SilentlyContinue | Where-Object {$_.SamAccountName -eq $nombreUsuario}
            
            if (-not $esMiembro) {
                Write-Host "        Añadiendo usuario '$nombreUsuario' al grupo '$nombreGrupo'..."
                Add-ADGroupMember -Identity $nombreGrupo -Members $nombreUsuario -ErrorAction SilentlyContinue
                Write-Host "        Usuario '$nombreUsuario' añadido al grupo '$nombreGrupo'"
            } else {
                Write-Host "        El usuario '$nombreUsuario' ya es miembro del grupo global '$nombreGrupo'"
            }
        }
    }
    # Registrar que hemos procesado este usuario y en qué OU está
    $usuariosProcesados[$nombreUsuario] = $unidadOrganizativa
    
    Write-Host "-> $nombreUsuario' completado"
    Write-Host "----------------------------------------"
 
}

# Generar resumen de usuarios, OUs y grupos
Write-Host "RESUMEN DE USUARIOS PROCESADOS"
Write-Host "----------------------------------------"

foreach ($nombreUsuario in $usuariosProcesados.Keys | Sort-Object) {
    $ou = $usuariosProcesados[$nombreUsuario]
    
    # Obtener grupos globales del usuario
    $usuario = Get-ADUser -Identity $nombreUsuario -Properties MemberOf, HomeDirectory, HomeDrive
    $grupos = @()
    
    foreach ($grupoPath in $usuario.MemberOf) {
        # Extraer nombre del grupo
        $grupoPath -match "CN=([^,]+)" | Out-Null
        $nombreGrupo = $Matches[1]
        
        # Verificar si es grupo global
        $grupo = Get-ADGroup -Identity $nombreGrupo -Properties GroupScope
        if ($grupo.GroupScope -eq "Global") {
            $grupos += $nombreGrupo
        }
    }
    
    # Mostrar información del usuario
    Write-Host "Usuario: $nombreUsuario"
    Write-Host "Unidad Organizativa: $ou"
    Write-Host "Directorio Home: $($usuario.HomeDirectory) (Unidad $($usuario.HomeDrive))"
    Write-Host "Grupos Globales: $(if($grupos){$grupos -join ', '}else{'Ninguno'})"
    Write-Host ""
}