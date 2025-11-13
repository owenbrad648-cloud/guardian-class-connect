import { useState, useEffect, useMemo } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { toast } from 'sonner';
import { Plus, Trash2, Pencil, Search, UserPlus, ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from '@/components/ui/alert-dialog';
import { ExcelImportDialog } from './ExcelImportDialog';
import { useSortableData } from '@/hooks/use-sortable-data';

interface Teacher {
  id: string;
  profile_id: string;
  profiles: {
    full_name: string;
    username: string;
    email: string | null;
  };
}

const TeachersManagement = () => {
  const [teachers, setTeachers] = useState<Teacher[]>([]);
  const [loading, setLoading] = useState(true); // General loading state
  const [actionLoading, setActionLoading] = useState(false); // Loading state specific to add/edit/delete actions
  const [open, setOpen] = useState(false);
  const [editingTeacher, setEditingTeacher] = useState<Teacher | null>(null);
  const [fullName, setFullName] = useState('');
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [searchTerm, setSearchTerm] = useState('');

  const { items: sortedItems, requestSort, sortConfig } = useSortableData(teachers, { key: 'profiles.full_name', direction: 'ascending' });

  useEffect(() => {
    fetchTeachers();
  }, []);

  const fetchTeachers = async () => {
    setLoading(true);
    const { data, error } = await supabase
      .from('teachers')
      .select('*, profiles(full_name, username, email)');

    if (error) {
      toast.error('خطا در بارگذاری معلم‌ها: ' + error.message);
    } else {
      setTeachers((data as Teacher[]) || []);
    }
    setLoading(false);
  };

  const handleAddOrEditTeacher = async (e: React.FormEvent) => {
    e.preventDefault();
    setActionLoading(true); // Start action loading

    if (editingTeacher) {
      // Logic for editing an existing teacher's profile (Only full_name is editable here)
      const { error: profileError } = await supabase
        .from('profiles')
        .update({ full_name: fullName })
        .eq('id', editingTeacher.profile_id);

      if (profileError) {
        toast.error('خطا در ویرایش پروفایل: ' + profileError.message);
        setActionLoading(false); // Stop loading on error
        return;
      }
      toast.success('معلم با موفقیت ویرایش شد');
    } else {
      // Use Edge Function for adding a new teacher
      const { data, error } = await supabase.functions.invoke<{
        success: boolean;
        successCount?: number;
        errors?: string[];
        results?: any[];
      }>('bulk-signup', {
        body: {
          userType: 'teacher',
          users: [{
            email,
            password,
            full_name: fullName,
            username: username,
          }]
        },
      });

      if (error || !data || !data.success) {
        // --- MODIFICATION: Display more specific error from Edge Function ---
        const errorMsgFromServer = data?.errors && data.errors.length > 0 ? data.errors[0] : null;
        const finalErrorMsg = errorMsgFromServer || error?.message || 'خطای ناشناخته در افزودن معلم';
        toast.error(`خطا در افزودن معلم: ${finalErrorMsg}`);
        // --- END MODIFICATION ---
        console.error("Add Teacher Error:", error, data);
        setActionLoading(false); // Stop loading on error
        return;
      }
      toast.success('معلم با موفقیت اضافه شد.');
    }

    setActionLoading(false); // Stop loading on success
    setOpen(false);
    resetForm();
    await fetchTeachers(); // Refresh list
  };

  const handleTeacherImport = async (importedData: any[]) => {
      const users = importedData.map(row => ({
          email: row.email,
          password: String(row.password),
          full_name: row.full_name,
          username: row.username,
      }));

      setActionLoading(true); // Indicate loading for import
      const { data, error } = await supabase.functions.invoke<{
          success: boolean;
          successCount?: number;
          errors?: string[];
          results?: any[];
      }>('bulk-signup', {
          body: {
            userType: 'teacher',
            users
          }
      });
      setActionLoading(false);

      if (error || !data) {
          const errorMsg = error?.message || "خطای سرور ناشناخته در وارد کردن معلم‌ها";
          toast.error(`خطا در وارد کردن: ${errorMsg}`);
          console.error("Import Error (Invoke):", error);
          return { success: false, errors: [errorMsg] };
      }

      // Display results summary
      let message = `${data.successCount || 0} معلم با موفقیت وارد شد.`;
      if (data.errors && data.errors.length > 0) {
          message += ` ${data.errors.length} خطا رخ داد.`;
          const firstErrors = data.errors.slice(0, 3).join('; ');
          toast.error(`خطا در وارد کردن برخی معلم‌ها.`, { description: firstErrors + (data.errors.length > 3 ? ' ... (مشاهده کنسول برای جزئیات)' : '') });
          console.error("Import Errors (Details):", data.errors);
      } else {
          toast.success(message);
      }

      await fetchTeachers();
      return { success: data.success && (!data.errors || data.errors.length === 0), errors: data.errors || [] };
  };


  const handleDeleteTeacher = async (teacher: Teacher) => {
    // **Simpler (but less robust) approach: Delete profile and teacher record only**
    setActionLoading(true);
    // 1. Delete teacher record
    const { error: teacherDeleteError } = await supabase.from('teachers').delete().eq('profile_id', teacher.profile_id);
    if (teacherDeleteError) {
        toast.error('خطا در حذف رکورد معلم: ' + teacherDeleteError.message);
        setActionLoading(false);
        return;
    }
    // 2. Delete profile record
    const { error: profileDeleteError } = await supabase.from('profiles').delete().eq('id', teacher.profile_id);
    if (profileDeleteError) {
        toast.error('خطا در حذف پروفایل معلم (رکورد معلم حذف شد): ' + profileDeleteError.message);
        setActionLoading(false);
        fetchTeachers(); // Refresh anyway
        return;
    }

     // TODO: Implement a secure server-side method (Edge Function or RPC) for deleting auth.users
     toast.success(`پروفایل و رکورد معلم (${teacher.profiles.full_name}) حذف شد.`);
     setActionLoading(false);
     fetchTeachers();
  };

  const openEditDialog = (teacher: Teacher) => {
    setEditingTeacher(teacher);
    setFullName(teacher.profiles.full_name);
    setUsername(teacher.profiles.username);
    setEmail(teacher.profiles.email || '');
    setPassword('');
    setOpen(true);
  };

  const resetForm = () => {
    setEditingTeacher(null);
    setFullName('');
    setUsername('');
    setEmail('');
    setPassword('');
  };

  const filteredTeachers = useMemo(() => {
    if (!sortedItems) return [];
    const lowerSearchTerm = searchTerm.toLowerCase();
    return sortedItems.filter(teacher =>
      teacher.profiles && (
          teacher.profiles.full_name?.toLowerCase().includes(lowerSearchTerm) ||
          teacher.profiles.username?.toLowerCase().includes(lowerSearchTerm) ||
          (teacher.profiles.email || '').toLowerCase().includes(lowerSearchTerm)
      )
    );
  }, [sortedItems, searchTerm]);

  const SortableHeader = ({ sortKey, children }: { sortKey: string, children: React.ReactNode }) => {
    const isSorted = sortConfig?.key === sortKey;
    const direction = sortConfig?.direction;
    const icon = !isSorted
        ? <ArrowUpDown className="mr-2 h-4 w-4 opacity-50" />
        : direction === 'ascending'
        ? <ArrowUp className="mr-2 h-4 w-4" />
        : <ArrowDown className="mr-2 h-4 w-4" />;
    return <Button variant="ghost" onClick={() => requestSort(sortKey)}>{children}{icon}</Button>
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex-1">
            <CardTitle>مدیریت معلم‌ها</CardTitle>
            <CardDescription>افزودن، ویرایش، حذف و جستجوی معلم‌ها</CardDescription>
          </div>
          <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
            <ExcelImportDialog
              triggerButton={<Button variant="outline" className="gap-2 flex-grow sm:flex-grow-0" disabled={actionLoading}><UserPlus className="w-4 h-4" />وارد کردن از فایل</Button>}
              requiredFields={{
                full_name: "نام کامل",
                username: "نام کاربری",
                email: "ایمیل",
                password: "رمز عبور"
              }}
              onImport={handleTeacherImport}
              templateFileName="teachers-template.xlsx"
            />
            <Dialog open={open} onOpenChange={(isOpen) => { setOpen(isOpen); if (!isOpen) resetForm(); }}>
              <DialogTrigger asChild><Button className="gap-2 flex-grow sm:flex-grow-0" disabled={actionLoading}><Plus className="w-4 h-4" />افزودن معلم</Button></DialogTrigger>
              <DialogContent dir="rtl">
                <DialogHeader><DialogTitle>{editingTeacher ? 'ویرایش معلم' : 'افزودن معلم جدید'}</DialogTitle></DialogHeader>
                <form onSubmit={handleAddOrEditTeacher} className="space-y-4 pt-4">
                  <div className="space-y-2">
                    <Label htmlFor="fullName">نام و نام خانوادگی</Label>
                    <Input id="fullName" value={fullName} onChange={(e) => setFullName(e.target.value)} required disabled={actionLoading} />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="email">ایمیل</Label>
                    <Input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required={!editingTeacher} disabled={!!editingTeacher || actionLoading} dir="ltr" className="text-left"/>
                    {editingTeacher && <p className="text-xs text-muted-foreground">ایمیل قابل ویرایش نیست.</p>}
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="username">نام کاربری</Label>
                    <Input id="username" value={username} onChange={(e) => setUsername(e.target.value)} required={!editingTeacher} disabled={!!editingTeacher || actionLoading} />
                     {editingTeacher && <p className="text-xs text-muted-foreground">نام کاربری قابل ویرایش نیست.</p>}
                  </div>
                  {!editingTeacher && (
                    <div className="space-y-2">
                      <Label htmlFor="password">رمز عبور</Label>
                      <Input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={6} disabled={actionLoading} />
                      <p className="text-xs text-muted-foreground">حداقل ۶ کاراکتر.</p>
                    </div>
                  )}
                  <Button type="submit" className="w-full" disabled={actionLoading}>
                    {actionLoading ? 'در حال پردازش...' : (editingTeacher ? 'ویرایش اطلاعات' : 'افزودن معلم')}
                  </Button>
                </form>
              </DialogContent>
            </Dialog>
          </div>
        </div>
        <div className="relative mt-4">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="جستجوی معلم (نام، کاربری، ایمیل)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10 w-full"
            dir="rtl"
          />
        </div>
      </CardHeader>
      <CardContent>
        {loading && teachers.length === 0 ? (
          <div className="text-center py-8">در حال بارگذاری...</div>
        ) : (
          <div className="overflow-x-auto border rounded-md">
            <Table dir="rtl">
              <TableHeader>
                <TableRow>
                  <TableHead className="text-right whitespace-nowrap"><SortableHeader sortKey="profiles.full_name">نام</SortableHeader></TableHead>
                  <TableHead className="text-right whitespace-nowrap"><SortableHeader sortKey="profiles.username">نام کاربری</SortableHeader></TableHead>
                  <TableHead className="text-right whitespace-nowrap"><SortableHeader sortKey="profiles.email">ایمیل</SortableHeader></TableHead>
                  <TableHead className="text-right whitespace-nowrap w-[100px]">عملیات</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredTeachers.length === 0 ? (
                  <TableRow><TableCell colSpan={4} className="h-24 text-center text-muted-foreground">هیچ معلمی یافت نشد.</TableCell></TableRow>
                ) : (
                  filteredTeachers.map((teacher) => (
                    teacher.profiles && (
                      <TableRow key={teacher.id} className="hover:bg-muted/50">
                        <TableCell className="font-medium">{teacher.profiles.full_name}</TableCell>
                        <TableCell>{teacher.profiles.username}</TableCell>
                        <TableCell dir="ltr" className="text-right">{teacher.profiles.email || '-'}</TableCell>
                        <TableCell>
                          <div className="flex items-center justify-end gap-2">
                            <Button variant="outline" size="icon" className="h-8 w-8" onClick={() => openEditDialog(teacher)} aria-label={`ویرایش ${teacher.profiles.full_name}`} disabled={actionLoading}>
                              <Pencil className="h-4 w-4" />
                            </Button>
                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button variant="destructive" size="icon" className="h-8 w-8" aria-label={`حذف ${teacher.profiles.full_name}`} disabled={actionLoading}>
                                  <Trash2 className="h-4 w-4" />
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent dir="rtl">
                                <AlertDialogHeader>
                                  <AlertDialogTitle>آیا از حذف مطمئن هستید؟</AlertDialogTitle>
                                  <AlertDialogDescription>
                                      این عمل پروفایل و رکورد معلم ({teacher.profiles.full_name}) را حذف می‌کند. این عمل ممکن است قابل بازگشت نباشد. (کاربر Auth ممکن است باقی بماند).
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>انصراف</AlertDialogCancel>
                                  <AlertDialogAction onClick={() => handleDeleteTeacher(teacher)} className="bg-destructive hover:bg-destructive/90">
                                    حذف
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                          </div>
                        </TableCell>
                      </TableRow>
                    )
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default TeachersManagement;