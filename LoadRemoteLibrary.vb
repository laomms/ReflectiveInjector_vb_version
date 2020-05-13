Imports System
Imports System.Runtime.InteropServices
Imports System.IO
Imports System.Diagnostics
Module LoadRemoteLibrary
	Private Function Rva2Offset(ByVal dwRva As UInteger, ByVal uiBaseAddress As IntPtr) As UInteger
		Dim dos_header As IMAGE_DOS_HEADER = Marshal.PtrToStructure(uiBaseAddress, GetType(IMAGE_DOS_HEADER))
		Dim pNtHeaders As IMAGE_NT_HEADERS32 = Marshal.PtrToStructure(IntPtr.Add(uiBaseAddress, dos_header.e_lfanew), GetType(IMAGE_NT_HEADERS32))

		Dim pSectionHeader As IMAGE_SECTION_HEADER
		Dim sizeOfSectionHeader = Marshal.SizeOf(pSectionHeader)
		Dim imageSectionPtr = IntPtr.Add(IntPtr.Add(uiBaseAddress, dos_header.e_lfanew), Marshal.OffsetOf(GetType(IMAGE_NT_HEADERS32), "OptionalHeader") + pNtHeaders.FileHeader.SizeOfOptionalHeader)
		pSectionHeader = Marshal.PtrToStructure(imageSectionPtr, GetType(IMAGE_SECTION_HEADER))
		If dwRva < pSectionHeader.PointerToRawData Then
			Return dwRva
		End If
		For wIndex As UShort = 0 To pNtHeaders.FileHeader.NumberOfSections - 1
			If dwRva >= pSectionHeader.VirtualAddress AndAlso dwRva < (pSectionHeader.VirtualAddress + pSectionHeader.SizeOfRawData) Then
				Return dwRva - pSectionHeader.VirtualAddress + pSectionHeader.PointerToRawData
			End If
		Next wIndex
		Return 0
	End Function
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
				'Dim imageSectionPtr = IntPtr.Add(IntPtr.Add(baseAddress, dos_header.e_lfanew), Marshal.OffsetOf(GetType(IMAGE_NT_HEADERS32), "OptionalHeader") + nt_header.FileHeader.SizeOfOptionalHeader)
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


	<StructLayout(LayoutKind.Sequential)>
	Public Structure IMAGE_DOS_HEADER
		Public e_magic As UInt16
		Public e_cblp As UInt16
		Public e_cp As UInt16
		Public e_crlc As UInt16
		Public e_cparhdr As UInt16
		Public e_minalloc As UInt16
		Public e_maxalloc As UInt16
		Public e_ss As UInt16
		Public e_sp As UInt16
		Public e_csum As UInt16
		Public e_ip As UInt16
		Public e_cs As UInt16
		Public e_lfarlc As UInt16
		Public e_ovno As UInt16
		<MarshalAs(UnmanagedType.ByValArray, SizeConst:=4)>
		Public e_res1 As UInt16()
		Public e_oemid As UInt16
		Public e_oeminfo As UInt16
		<MarshalAs(UnmanagedType.ByValArray, SizeConst:=10)>
		Public e_res2 As UInt16()
		Public e_lfanew As Int32
	End Structure
	<StructLayout(LayoutKind.Sequential)>
	Public Structure IMAGE_FILE_HEADER
		Public Machine As UShort                        '标识CPU的数字。运行平台。
		Public NumberOfSections As UShort               '节的数目。Windows加载器限制节的最大数目为96。文件区块数目。
		Public TimeDateStamp As UInteger                '文件创建日期和时间,UTC时间1970年1月1日00:00起的总秒数的低32位。
		Public PointerToSymbolTable As UInteger         '指向符号表（主要用于调试）,已废除。
		Public NumberOfSymbols As UInteger              '符号表中符号个数，已废除。
		Public SizeOfOptionalHeader As UShort           'IMAGE_OPTIONAL_HEADER32 结构大小，可选头大小。
		Public Characteristics As UShort                '文件属性，文件特征值。
	End Structure
	<StructLayout(LayoutKind.Sequential)>
	Public Structure IMAGE_NT_HEADERS32
		Public Signature As UInteger                        '4   ubytes PE文件头标志：(e_lfanew)->‘PE\0\0’
		Public FileHeader As IMAGE_FILE_HEADER              '20  ubytes PE文件物理分布的信息
		Public OptionalHeader As IMAGE_OPTIONAL_HEADER32    '224 ubytes PE文件逻辑分布的信息
	End Structure
	<StructLayout(LayoutKind.Sequential)>
	Public Structure IMAGE_OPTIONAL_HEADER32
		Public Magic As UShort                           ' 标志字, 0x0107表明这是一个ROM 映像,0x10B表明这是一个32位镜像文件。，0x20B表明这是一个64位镜像文件。
		Public MajorLinkerVersion As Byte                ' 链接程序的主版本号
		Public MinorLinkerVersion As Byte                ' 链接程序的次版本号
		Public SizeOfCode As UInteger                    ' 所有含代码的节的总大小
		Public SizeOfInitializedData As UInteger         ' 所有含已初始化数据的节的总大小
		Public SizeOfUninitializedData As UInteger       ' 所有含未初始化数据的节的大小
		Public AddressOfEntryPoint As UInteger           ' 程序执行入口RVA
		Public BaseOfCode As UInteger                    ' 代码的区块的起始RVA
		Public BaseOfData As UInteger                    ' 数据的区块的起始RVA
		Public ImageBase As UInteger                     ' 程序的首选装载地址
		Public SectionAlignment As UInteger              ' 内存中的区块的对齐大小
		Public FileAlignment As UInteger                 ' 文件中的区块的对齐大小
		Public MajorOperatingSystemVersion As UShort     ' 要求操作系统最低版本号的主版本号
		Public MinorOperatingSystemVersion As UShort     ' 要求操作系统最低版本号的副版本号
		Public MajorImageVersion As UShort               ' 可运行于操作系统的主版本号
		Public MinorImageVersion As UShort               ' 可运行于操作系统的次版本号
		Public MajorSubsystemVersion As UShort           ' 要求最低子系统版本的主版本号
		Public MinorSubsystemVersion As UShort           ' 要求最低子系统版本的次版本号
		Public Win32VersionValue As UInteger             ' 莫须有字段，不被病毒利用的话一般为0
		Public SizeOfImage As UInteger                   ' 映像装入内存后的总尺寸
		Public SizeOfHeaders As UInteger                 ' 所有头 + 区块表的尺寸大小
		Public CheckSum As UInteger                      ' 映像的校检和
		Public Subsystem As UShort                       ' 可执行文件期望的子系统
		Public DllCharacteristics As UShort              ' DllMain()函数何时被调用，默认为 0
		Public SizeOfStackReserve As UInteger            ' 初始化时的栈大小
		Public SizeOfStackCommit As UInteger             ' 初始化时实际提交的栈大小
		Public SizeOfHeapReserve As UInteger             ' 初始化时保留的堆大小
		Public SizeOfHeapCommit As UInteger              ' 初始化时实际提交的堆大小
		Public LoaderFlags As UInteger                   ' 与调试有关，默认为 0 
		Public NumberOfRvaAndSizes As UInteger           ' 下边数据目录的项数，这个字段自Windows NT 发布以来一直是16
		Public IMAGE_DIRECTORY_ENTRY_EXPORT As IMAGE_DATA_DIRECTORY         '导出表
		Public IMAGE_DIRECTORY_ENTRY_IMPORT As IMAGE_DATA_DIRECTORY         '导入表
		Public IMAGE_DIRECTORY_ENTRY_RESOURCE As IMAGE_DATA_DIRECTORY       '资源目录
		Public IMAGE_DIRECTORY_ENTRY_EXCEPTION As IMAGE_DATA_DIRECTORY      '异常目录
		Public IMAGE_DIRECTORY_ENTRY_SECURITY As IMAGE_DATA_DIRECTORY       '安全目录
		Public IMAGE_DIRECTORY_ENTRY_BASERELOC As IMAGE_DATA_DIRECTORY      '重定位基本表
		Public IMAGE_DIRECTORY_ENTRY_DEBUG As IMAGE_DATA_DIRECTORY          '调试目录
		Public IMAGE_DIRECTORY_ENTRY_COPYRIGHT As IMAGE_DATA_DIRECTORY      '描述字符串
		Public IMAGE_DIRECTORY_ENTRY_ARCHITECTURE As IMAGE_DATA_DIRECTORY   '机器值
		Public IMAGE_DIRECTORY_ENTRY_GLOBALPTR As IMAGE_DATA_DIRECTORY      '线程本地存储
		Public IMAGE_DIRECTORY_ENTRY_TLS As IMAGE_DATA_DIRECTORY            'TLS目录
		Public IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG As IMAGE_DATA_DIRECTORY    '载入配置目录
		Public IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT As IMAGE_DATA_DIRECTORY   '绑定倒入表
		Public IMAGE_DIRECTORY_ENTRY_IAT As IMAGE_DATA_DIRECTORY            '导入地址表
		Public IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT As IMAGE_DATA_DIRECTORY   '延迟倒入表
		Public IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR As IMAGE_DATA_DIRECTORY 'COM描述符
	End Structure
	<StructLayout(LayoutKind.Sequential)>
	Public Structure IMAGE_DATA_DIRECTORY
		Public VirtualAddress As UInteger      '地址
		Public Size As UInteger                '大小
	End Structure
	Public Structure Misc
		Public PhysicalAddress As System.UInt32
		Public VirtualSize As System.UInt32
	End Structure
	Public Structure IMAGE_SECTION_HEADER
		Public Name As System.Byte
		Public Misc As Misc
		Public VirtualAddress As System.UInt32
		Public SizeOfRawData As System.UInt32
		Public PointerToRawData As System.UInt32
		Public PointerToRelocations As System.UInt32
		Public PointerToLinenumbers As System.UInt32
		Public NumberOfRelocations As System.UInt16
		Public NumberOfLinenumbers As System.UInt16
		Public Characteristics As System.UInt32
	End Structure
	<StructLayout(LayoutKind.Sequential)>
	Public Structure IMAGE_EXPORT_DIRECTORY
		Public Characteristics As UInteger             '未使用,为0
		Public TimeDateStamp As UInteger               '文件生成时间
		Public MajorVersion As UShort                  '未使用,为0
		Public MinorVersion As UShort                  '未使用,为0
		Public Name As UInteger                        '这是这个PE文件的模块名
		Public Base As UInteger                        '基数，加上序数就是函数地址数组的索引值
		Public NumberOfFunctions As UInteger           '导出函数的个数
		Public NumberOfNames As UInteger               '以名称方式导出的函数的总数（有的函数没有名称只有序数）
		Public AddressOfFunctions As UInteger          'RVA from base of image Nt头基址加上这个偏移得到的数组中存放所有的导出地址表
		Public AddressOfNames As UInteger              'RVA from base of image Nt头基址加上这个偏移得到的数组中存放所有的名称字符串
		Public AddressOfNameOrdinals As UInteger       'RVA from base of image Nt头基址加上这个偏移得到的数组中存放所有的函数序号，并不一定是连续的，但一般和导出地址表是一一对应的
	End Structure
	<StructLayout(LayoutKind.Explicit)>
	Public Structure IMAGE_THUNK_DATA32
		<FieldOffset(0)> Public ForwarderString As UInteger
		<FieldOffset(0)> Public [Function] As UInteger
		<FieldOffset(0)> Public Ordinal As UInteger
		<FieldOffset(0)> Public AddressOfData As UInteger
	End Structure
	Public Structure IMAGE_IMPORT_DESCRIPTOR
		Public OriginalFirstThunk As UInteger
		Public TimeDateStamp As UInteger               ' 0 If Not bound, -1 if bound, And real date\time stamp in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (New BIND) O.W. date/time stamp of DLL bound to (Old BIND)  
		Public ForwarderChain As UInteger              ' -1 If no forwarders  
		Public Name As UInteger                        ' Dll Name
		Public FirstThunk As UInteger                  ' RVA To IAT (If bound this IAT has actual addresses)  
	End Structure
	<StructLayout(LayoutKind.Sequential)>
	Public Structure IMAGE_IMPORT_BY_NAME
		Public Hint As Short
		Public Name As Byte
	End Structure
	<DllImport("dbghelp", SetLastError:=True)>
	Public Function ImageRvaToVa(ByVal NtHeaders As IntPtr, ByVal Base As IntPtr, ByVal Rva As UInteger, ByVal LastRvaSection As Integer) As IntPtr
	End Function
End Module
